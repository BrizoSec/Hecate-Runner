"""Exercise storage, retries, remote verification, and pipeline output ordering."""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.cti.misp import _is_published
from hecate_runner.misp_publisher import (
    MispPublishError,
    enqueue_misp_hunt,
    misp_publication_status,
    sync_misp_outbox,
)
from hecate_runner.orchestrator import Orchestrator


@pytest.fixture
def export_settings(settings: Settings) -> Settings:
    settings.misp_publishing_enabled = True
    settings.misp_base_url = "https://misp.test"
    settings.misp_api_key = "secret-export-key"
    hunt = settings.hunts_root / "2026/Q3/H-0001.md"
    hunt.write_text(
        '---\nhunt_id: H-0001\ntitle: "Candidate hunt"\ndate: 2026-10-30\nspawned_from: R-0001\n---\n\nReview required.\n'
    )
    (settings.hecate_workspace / "research").mkdir()
    (settings.hecate_workspace / "research/R-0001.md").write_text("# Retained research\n")
    query = settings.hecate_workspace / "queries/H-0001"
    query.mkdir(parents=True)
    (query / "rule.yml").write_text("title: Candidate rule\n")
    (query / "rule.leql").write_text("where(process.name=wscript.exe)\n")
    return settings


class FakeMisp:
    def __init__(self) -> None:
        self.events: dict[str, dict] = {}
        self.requests: list[httpx.Request] = []
        self.lose_create_response = False
        self.drop_reports = False
        self.drop_attachment_data = False
        self.reject = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["Authorization"] == "secret-export-key"
        if self.reject:
            return httpx.Response(403, json={"error": "secret-export-key"})
        if request.method == "GET":
            event = self.events.get(request.url.path.rsplit("/", 1)[-1])
            return httpx.Response(200, json={"Event": event}) if event else httpx.Response(404)
        event = json.loads(request.content)["Event"]
        event["id"] = "123"
        self.events[event["uuid"]] = event
        if self.drop_reports:
            event["EventReport"] = []
        if self.drop_attachment_data:
            for attribute in event["Attribute"]:
                attribute.pop("data", None)
        if request.url.path == "/events/add" and self.lose_create_response:
            self.lose_create_response = False
            return httpx.Response(503)
        return httpx.Response(200, json={"Event": event})

    def client(self) -> httpx.Client:
        return httpx.Client(
            base_url="https://misp.test",
            headers={"Authorization": "secret-export-key"},
            transport=httpx.MockTransport(self.handler),
        )


def test_stores_all_artifacts_reports_and_typed_provenance(export_settings: Settings) -> None:
    s = export_settings
    records = [
        {
            "type": "domain",
            "value": "evil[.]example",
            "role": "c2",
            "status": "historical",
            "source": "https://source.example/report",
        },
        {"type": "ipv4", "value": "203.0.113.4", "role": "inbound"},
        {"type": "sha256", "value": "a" * 64, "role": "document"},
        {"type": "sha256", "value": "b" * 64, "role": "non_file"},
        {"type": "url", "value": "https://["},
    ]
    enqueue_misp_hunt(s, "H-0001", indicator_records=records)
    remote = FakeMisp()
    assert sync_misp_outbox(s, client=remote.client()) == [{"hunt_id": "H-0001", "event_id": "123"}]
    event = next(iter(remote.events.values()))
    assert event["published"] is False and event["distribution"] == "0"
    assert event["analysis"] == "0"
    attachments = [a for a in event["Attribute"] if a["type"] == "attachment"]
    assert {a["value"] for a in attachments} == {"H-0001.md", "R-0001.md", "rule.yml", "rule.leql"}
    assert (
        base64.b64decode(next(a for a in attachments if a["value"] == "rule.leql")["data"])
        == b"where(process.name=wscript.exe)\n"
    )
    assert len(event["EventReport"]) == 3
    assert all(a["to_ids"] is False for a in event["Attribute"])
    assert any(
        a["type"] == "domain" and a["value"] == "evil.example" and "historical" in a["comment"]
        for a in event["Attribute"]
    )
    assert any(a["type"] == "ip-src" for a in event["Attribute"])
    assert not any(a["value"] == "b" * 64 for a in event["Attribute"])
    assert misp_publication_status(s)[0]["status"] == "confirmed"


def test_repeated_snapshot_is_noop_and_edits_reuse_event(export_settings: Settings) -> None:
    s = export_settings
    remote = FakeMisp()
    enqueue_misp_hunt(s, "H-0001")
    sync_misp_outbox(s, client=remote.client())
    event_uuid = next(iter(remote.events))
    request_count = len(remote.requests)
    assert enqueue_misp_hunt(s, "H-0001") == "confirmed"
    assert sync_misp_outbox(s, client=remote.client()) == []
    assert len(remote.requests) == request_count
    hunt = s.hunts_root / "2026/Q3/H-0001.md"
    hunt.write_text(hunt.read_text() + "\nAnalyst update.\n")
    enqueue_misp_hunt(s, "H-0001")
    sync_misp_outbox(s, client=remote.client())
    assert list(remote.events) == [event_uuid]
    assert remote.requests[-2].url.path == "/events/edit/123"
    assert "Analyst update." in remote.events[event_uuid]["EventReport"][0]["content"]


def test_output_uses_its_writer_credential_not_intake_key(
    export_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hecate_runner import misp_publisher as module

    s = export_settings
    s.misp_api_key = "read-only-intake-key"
    s.misp_output_api_key = "secret-export-key"
    remote = FakeMisp()
    client = remote.client()
    constructed = []

    def factory(**kwargs):
        constructed.append(kwargs)
        return client

    monkeypatch.setattr(module.httpx, "Client", factory)
    enqueue_misp_hunt(s, "H-0001")
    assert sync_misp_outbox(s)
    assert constructed[0]["headers"]["Authorization"] == "secret-export-key"
    assert s.misp_api_key == "read-only-intake-key"


def test_lost_create_response_retries_existing_event_without_duplicates(
    export_settings: Settings,
) -> None:
    s = export_settings
    remote = FakeMisp()
    remote.lose_create_response = True
    enqueue_misp_hunt(s, "H-0001")
    assert sync_misp_outbox(s, client=remote.client()) == []
    row = misp_publication_status(s)[0]
    assert row["status"] == "pending" and row["attempts"] == 1
    assert row["last_error"] == "MISP HTTP 503"
    with sqlite3.connect(s.hecate_workspace / ".hecate/misp/outbox.sqlite3") as db:
        db.execute("UPDATE exports SET next_attempt=0")
    assert sync_misp_outbox(s, client=remote.client())
    assert len(remote.events) == 1
    assert sum(r.url.path == "/events/add" for r in remote.requests) == 1


@pytest.mark.parametrize("failure", ["drop_reports", "drop_attachment_data", "reject"])
def test_unverified_or_rejected_output_remains_pending(
    export_settings: Settings, failure: str
) -> None:
    s = export_settings
    remote = FakeMisp()
    setattr(remote, failure, True)
    enqueue_misp_hunt(s, "H-0001")
    assert sync_misp_outbox(s, client=remote.client()) == []
    row = misp_publication_status(s)[0]
    assert row["status"] == "pending" and row["event_id"] is None
    assert "secret-export-key" not in json.dumps(row)


def test_disabled_output_never_sends_or_creates_queue(export_settings: Settings) -> None:
    s = export_settings
    s.misp_publishing_enabled = False
    remote = FakeMisp()
    with pytest.raises(MispPublishError, match="disabled"):
        enqueue_misp_hunt(s, "H-0001")
    assert sync_misp_outbox(s, client=remote.client()) == []
    assert not remote.requests
    assert not (s.hecate_workspace / ".hecate/misp/outbox.sqlite3").exists()


def test_linked_artifact_outside_workspace_is_rejected(
    export_settings: Settings, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.leql"
    outside.write_text("private configuration")
    (export_settings.hecate_workspace / "queries/H-0001/escape.leql").symlink_to(outside)
    with pytest.raises(RuntimeError, match="outside"):
        enqueue_misp_hunt(export_settings, "H-0001")


def test_own_events_are_never_reingested_even_if_manually_published() -> None:
    assert not _is_published({"info": "Hecate Hunt: H-0911 - Candidate", "published": True})
    assert _is_published({"info": "External intelligence", "published": True})


def test_cli_publish_and_status_report_confirmed_storage(
    export_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from hecate_runner import cli

    remote = FakeMisp()
    monkeypatch.setattr(cli, "Settings", lambda: export_settings)
    from hecate_runner import misp_publisher as module

    real_sync = sync_misp_outbox
    monkeypatch.setattr(
        module, "sync_misp_outbox", lambda settings: real_sync(settings, client=remote.client())
    )
    runner = CliRunner()
    result = runner.invoke(cli.app, ["misp", "publish", "H-0001"])
    assert result.exit_code == 0, result.stdout
    assert "confirmed MISP event #123" in result.stdout
    result = runner.invoke(cli.app, ["misp", "status", "--json"])
    assert result.exit_code == 0
    status = json.loads(result.stdout)
    assert status["enabled"] and status["exports"][0]["status"] == "confirmed"


def test_digest_sync_requires_a_confirmed_export_not_just_credentials(
    export_settings: Settings,
) -> None:
    from hecate_runner.digests import collect_threat_intel_metrics

    s = export_settings
    assert not collect_threat_intel_metrics(s)["misp_sync_active"]
    enqueue_misp_hunt(s, "H-0001")
    assert not collect_threat_intel_metrics(s)["misp_sync_active"]
    sync_misp_outbox(s, client=FakeMisp().client())
    assert collect_threat_intel_metrics(s)["misp_sync_active"]
    s.misp_publishing_enabled = False
    assert not collect_threat_intel_metrics(s)["misp_sync_active"]


def test_pipeline_exports_after_sigma_and_isolates_outage(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hecate_runner import orchestrator as module

    settings.misp_publishing_enabled = True
    settings.sigma_generation_enabled = True
    calls = []

    def attach(self, req, path, item, facts):
        path.write_text(path.read_text() + "\nFinal Sigma output.\n")

    def enqueue(s, hunt_id, **kwargs):
        hunt = next(s.hunts_root.rglob(f"{hunt_id}.md"))
        assert "Final Sigma output." in hunt.read_text()
        calls.append("enqueue")

    def sync(s):
        calls.append("sync")
        if len(calls) > 1:
            raise MispPublishError("MISP HTTP 503")
        return []

    monkeypatch.setattr(Orchestrator, "_attach_sigma_rules", attach)
    monkeypatch.setattr(module, "enqueue_misp_hunt", enqueue)
    monkeypatch.setattr(module, "sync_misp_outbox", sync)
    result = Orchestrator(
        settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti
    ).run_once()
    assert result.outcome == "draft_created"
    assert calls == ["sync", "enqueue", "sync"]


def test_dry_run_does_not_export(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hecate_runner import orchestrator as module

    settings.misp_publishing_enabled = True
    export = MagicMock()
    monkeypatch.setattr(module, "sync_misp_outbox", export)
    monkeypatch.setattr(module, "enqueue_misp_hunt", export)
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti).run_once(
        dry_run=True
    )
    export.assert_not_called()
