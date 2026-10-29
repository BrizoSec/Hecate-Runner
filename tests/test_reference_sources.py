"""Repository intake durability, risk gates and literal evidence safety."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from hecate_runner.config import Settings
from hecate_runner.cti import get_provider
from hecate_runner.cti.attack_deltas import AttackDeltaProvider
from hecate_runner.cti.catalogs import GTFOBinsProvider, LolbasProvider, LolDriversProvider
from hecate_runner.cti.cisa_advisories import BROWSER_UA, CisaAdvisoryProvider, CisaICSProvider
from hecate_runner.cti.nuclei import NucleiProvider
from hecate_runner.cti.reference_rules import reference_candidates, template_requests
from hecate_runner.purple_team import replay_events

OLD, NEW = "a" * 40, "b" * 40


class CatalogServer:
    def __init__(self) -> None:
        self.revision = OLD
        self.entries = {"yml/a.yml": "1", "yml/b.yml": "2"}
        self.fail = False
        self.truncated = False
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "api.github.com":
            if "/commits/" in request.url.path:
                return httpx.Response(200, json={"sha": self.revision})
            return httpx.Response(
                200,
                json={
                    "truncated": self.truncated,
                    "tree": [
                        {"path": p, "sha": sha, "type": "blob"} for p, sha in self.entries.items()
                    ],
                },
            )
        if self.fail:
            return httpx.Response(503)
        return httpx.Response(
            200,
            text="Name: Certutil.exe\nCommands:\n- Command: certutil.exe -urlcache -split -f {REMOTEURL}\n",
        )


def catalog(tmp_path: Path) -> tuple[LolbasProvider, CatalogServer]:
    server = CatalogServer()
    provider = LolbasProvider(
        tmp_path,
        client=httpx.Client(transport=httpx.MockTransport(server)),
        interval_seconds=0,
        github_token="secret-test",
    )
    return provider, server


def test_baseline_then_commit_deltas_survive_restart_and_individual_ack(tmp_path: Path) -> None:
    provider, server = catalog(tmp_path)
    assert provider.next_item() is None
    server.revision, server.entries = NEW, {"yml/a.yml": "3", "yml/b.yml": "4"}
    first = provider.next_item()
    assert first and first.metadata["processing_track"] == "deep"
    assert NEW in first.source_url
    assert provider.next_item().identifier == first.identifier
    provider.acknowledge(first)
    restarted = LolbasProvider(tmp_path, client=provider.client, interval_seconds=0)
    second = restarted.next_item()
    assert second and second.identifier != first.identifier
    restarted.acknowledge(second)
    assert restarted.next_item() is None
    assert restarted.load()["revision"] == NEW
    for request in server.requests:
        if request.url.host != "api.github.com":
            assert "authorization" not in request.headers
    assert any("authorization" in request.headers for request in server.requests)


def test_fetch_error_and_truncated_tree_preserve_cursor(tmp_path: Path) -> None:
    provider, server = catalog(tmp_path)
    provider.next_item()
    original = provider.cursor_file.read_text()
    server.revision, server.truncated = NEW, True
    with pytest.raises(ValueError, match="truncated"):
        provider.next_item()
    assert provider.cursor_file.read_text() == original
    server.truncated, server.fail = False, True
    server.entries["yml/a.yml"] = "3"
    with pytest.raises(httpx.HTTPStatusError):
        provider.next_item()
    assert len(provider.load()["pending"]) == 1
    assert not json.loads((tmp_path / ".hecate/integrations/lolbas.json").read_text())["healthy"]
    server.fail = False
    assert provider.next_item()


def test_corrupt_cursor_is_not_silently_rebaselined(tmp_path: Path) -> None:
    provider, _ = catalog(tmp_path)
    provider.cursor_file.parent.mkdir()
    provider.cursor_file.write_text("broken")
    with pytest.raises(ValueError):
        provider.next_item()
    assert provider.cursor_file.read_text() == "broken"


def test_catalog_schemas_context_and_no_bare_binary_candidates(tmp_path: Path) -> None:
    provider = GTFOBinsProvider(tmp_path)
    assert provider.relevant("_gtfobins/bash")
    data = {
        "functions": {
            "shell": [{"code": "bash -p", "contexts": {"sudo": {"code": "sudo bash -p"}}}]
        }
    }
    item = provider.build_item(data, yaml.safe_dump(data), "_gtfobins/bash", NEW)
    values = [a["value"] for a in item.metadata["source_artifacts"]]
    assert values == ["bash -p", "sudo bash -p"]
    assert item.metadata["reference_only"]
    assert "contexts:" in item.content
    driver = LolDriversProvider(tmp_path)
    data = {
        "Commands": {"Command": "sc.exe create vulnerable type= kernel"},
        "KnownVulnerableSamples": [{"SHA256": "a" * 64}],
    }
    item = driver.build_item(data, yaml.safe_dump(data), "yaml/uuid.yaml", NEW)
    assert item.metadata["sha256"] == ["a" * 64]
    assert item.metadata["source_artifacts"][0]["value"].startswith("sc.exe create")
    assert (
        reference_candidates(
            {"evidence_profile": "behavior_catalog", "source_artifacts": [{"value": "whoami.exe"}]}
        )
        == []
    )
    provider.close()
    driver.close()


def template() -> dict[str, Any]:
    return {
        "id": "CVE-2024-3400",
        "info": {
            "name": "Probe",
            "classification": {"cve-id": "CVE-2024-3400", "epss-score": 0.99},
        },
        "http": [
            {
                "method": "PUT",
                "path": ["{{BaseURL}}/api/upload?x=1"],
                "headers": {"X-Test": "exact"},
                "matchers": [{"type": "word", "words": ["response-secret"]}],
            }
        ],
    }


def nuclei(
    tmp_path: Path, *, kev: bool = False, score: float = 0.01, fail: bool = False, date: str = ""
) -> NucleiProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        if fail:
            return httpx.Response(503)
        if request.url.host == "www.cisa.gov":
            return httpx.Response(
                200, json={"vulnerabilities": [{"cveID": "CVE-2024-3400"}] if kev else []}
            )
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2024-3400",
                        "epss": score,
                        "percentile": 0.99,
                        "date": date or datetime.now(UTC).date().isoformat(),
                    }
                ]
            },
        )

    return NucleiProvider(tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)))


@pytest.mark.parametrize(
    ("kev", "score", "expected"), [(True, 0.01, True), (False, 0.9, True), (False, 0.01, False)]
)
def test_nuclei_live_risk_gate_ignores_embedded_epss(
    tmp_path: Path, kev: bool, score: float, expected: bool
) -> None:
    provider = nuclei(tmp_path, kev=kev, score=score)
    data = template()
    item = provider.build_item(data, yaml.safe_dump(data), "http/cves/2024/CVE-2024-3400.yaml", NEW)
    assert bool(item) is expected
    if item:
        assert item.metadata["http_requests"] == data["http"]
        assert item.metadata["reference_only"]


def test_nuclei_risk_outages_staleness_and_missing_cve(tmp_path: Path) -> None:
    data = template()
    with pytest.raises(httpx.HTTPStatusError):
        nuclei(tmp_path, fail=True).build_item(data, yaml.safe_dump(data), "test.yaml", NEW)
    with pytest.raises(ValueError, match="stale"):
        nuclei(tmp_path, date="2020-01-01").build_item(data, yaml.safe_dump(data), "test.yaml", NEW)
    data["info"]["classification"] = {}
    assert nuclei(tmp_path, fail=True).build_item(data, "", "test.yaml", NEW) is None


def test_exact_request_candidates_replay_no_guessed_method_or_response_matcher() -> None:
    requests = template()["http"]
    candidates = reference_candidates({"http_requests": requests})
    selection = candidates[0]["detection"]["selection"]
    assert selection == {"cs-method": "PUT", "cs-uri-stem": "/api/upload", "cs-uri-query": "x=1"}
    events = replay_events(
        [], [], cti_text="/api/login response-secret", http_requests=requests, enable_atomic=False
    )
    assert events["webserver"] == [
        {
            "cs-method": "PUT",
            "cs-uri-stem": "/api/upload",
            "cs-uri-query": "x=1",
            "c-uri": "/api/upload?x=1",
        }
    ]
    assert "response-secret" not in str(candidates) + str(events)
    assert template_requests([{"method": "POST", "path": ["{{BaseURL}}/api/{{randstr}}"]}]) == []
    assert template_requests(
        [{"raw": ["PATCH /console/probe HTTP/1.1\nHost: {{Hostname}}\nX: exact"]}]
    ) == [{"method": "PATCH", "uri": "/console/probe"}]


def csaf() -> dict[str, Any]:
    return {
        "document": {
            "publisher": {"name": "CISA"},
            "tracking": {"id": "icsa-26-001", "version": "2"},
            "title": "Controller vulnerability",
            "distribution": {"tlp": {"label": "WHITE"}},
            "notes": [{"text": "Monitor controller configuration changes."}],
        },
        "vulnerabilities": [{"cve": "CVE-2026-12345"}],
    }


def test_cisa_ics_csaf_preserves_official_document(tmp_path: Path) -> None:
    provider = CisaICSProvider(tmp_path)
    item = provider.build_item(csaf(), json.dumps(csaf()), "csaf_files/OT/white/test.json", NEW)
    assert item.metadata["is_ics"] and item.metadata["advisory_version"] == "2"
    assert item.metadata["tlp"] == "CLEAR"
    assert "Monitor controller configuration" in item.content
    assert item.metadata["structured_document"] == csaf()
    provider.close()


def test_cisa_dedicated_browser_feed_baseline_then_full_advisory(tmp_path: Path) -> None:
    phase = [1]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            if "/commits/" in request.url.path:
                return httpx.Response(200, json={"sha": OLD})
            return httpx.Response(
                200,
                json={"tree": [{"type": "blob", "path": "csaf_files/IT/test.json", "sha": "x"}]},
            )
        assert request.headers["User-Agent"] == BROWSER_UA
        if request.url.path.endswith(".xml"):
            return httpx.Response(
                200,
                text=f"<rss><channel><item><title>CISA AA</title><link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa-test</link><pubDate>{phase[0]}</pubDate></item></channel></rss>",
            )
        return httpx.Response(
            200,
            text="<html><main>"
            + "Detailed adversary procedure and detection guidance. " * 12
            + "</main></html>",
        )

    provider = CisaAdvisoryProvider(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)), interval_seconds=0
    )
    assert provider.next_item() is None
    phase[0] = 2
    item = provider.next_item()
    assert item and item.metadata["cisa_feed"]
    assert "Detailed adversary" in item.content and "html" not in item.content
    provider.acknowledge(item)
    assert provider.next_item() is None


def bundle(
    description: str = "Original technique",
    *,
    procedure: bool = False,
    modified: str = "2026-01-01",
    revoked: bool = False,
) -> dict[str, Any]:
    technique = {
        "id": "attack-pattern--one",
        "type": "attack-pattern",
        "name": "Test technique",
        "description": description,
        "modified": modified,
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        "revoked": revoked,
    }
    objects = [technique]
    if procedure:
        objects.append(
            {
                "id": "relationship--one",
                "type": "relationship",
                "relationship_type": "uses",
                "target_ref": technique["id"],
                "source_ref": "malware--one",
                "description": "Malware executes a documented PowerShell command.",
            }
        )
    return {"type": "bundle", "objects": objects}


def test_attack_monthly_delta_ignores_version_noise_and_checks_corpus_coverage(
    tmp_path: Path,
) -> None:
    current = [bundle()]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.host == "api.github.com":
            return httpx.Response(200, json={"sha": NEW})
        return httpx.Response(200, json=current[0])

    provider = AttackDeltaProvider(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)), interval_seconds=0
    )
    assert provider.next_item() is None
    current[0] = bundle(modified="2026-02-01")
    assert provider.next_item() is None
    current[0] = bundle(procedure=True)
    item = provider.next_item()
    assert item and item.metadata["technique_id"] == "T1059.001"
    assert NEW in item.source_url
    assert item.metadata["delta"]["procedures"]
    assert any("/ics-attack/" in c for c in calls)
    (tmp_path / "hunts").mkdir()
    (tmp_path / "hunts/H-0001.md").write_text("---\nstatus: active\ntechniques: [T1059.001]\n---\n")
    assert provider.next_item() is None  # Newly covered pending work is not drafted.
    before = len(calls)
    provider.interval_seconds = 30 * 86400
    assert provider.next_item() is None
    assert len(calls) == before


@pytest.mark.parametrize(
    "name",
    ["lolbas", "loldrivers", "gtfobins", "nuclei", "cisa_advisories", "cisa_ics", "attack_deltas"],
)
def test_new_source_factory_and_settings(tmp_path: Path, name: str) -> None:
    settings = Settings(_env_file=None, hecate_workspace=tmp_path, cti_provider=name)
    provider = get_provider(name, settings=settings)
    assert provider.name == name
    provider.close()


def test_catalog_enrichments_keep_capability_separate_and_cache_driver_hashes(
    tmp_path: Path,
) -> None:
    provider, server = catalog(tmp_path)
    server.entries = {"yml/Certutil.yml": "1", "yml/Whoami.yml": "2"}
    matches = provider.enrich(
        "Adversaries invoked Certutil.exe -urlcache for downloading a payload"
    )
    assert len(matches) == 1 and matches[0]["revision"] == OLD
    assert "not evidence of use" in matches[0]["meaning"]
    assert provider.load()["pending"] == []
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200, json=[{"Id": "one", "KnownVulnerableSamples": [{"SHA256": "c" * 64}]}]
        )

    driver = LolDriversProvider(
        tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert driver.enrich("no hash in this report") == []
    assert not calls
    first = driver.enrich("c" * 64)
    assert len(first) == 1 and len(first[0]["snapshot_sha256"]) == 64
    assert driver.enrich("c" * 64) == first
    assert len(calls) == 1


def test_intentional_nuclei_filter_retains_reason_and_outage_retains_pending(
    tmp_path: Path,
) -> None:
    provider = nuclei(tmp_path, score=0.01)
    data = template()
    assert provider.build_item(data, yaml.safe_dump(data), "template.yaml", NEW) is None
    decision = json.loads((tmp_path / ".hecate/source-decisions/nuclei.json").read_text())[0]
    assert decision["reason"] == "below risk threshold" and decision["revision"] == NEW
    provider.cursor_file.parent.mkdir(exist_ok=True)
    state = {
        "revision": OLD,
        "next_revision": NEW,
        "entries": {},
        "next_entries": {},
        "pending": [{"path": "template.yaml", "blob": "abc"}],
    }
    provider.save(state)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "raw.githubusercontent.com":
            return httpx.Response(200, text=yaml.safe_dump(data))
        return httpx.Response(503)

    failing = NucleiProvider(tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(httpx.HTTPStatusError):
        failing.next_item()
    assert failing.load() == state


def test_gtfobins_frontmatter_fence_is_a_line_not_a_command_substring(tmp_path: Path) -> None:
    body = "---\nfunctions:\n  shell:\n  - code: printf '---'\n---\nPage prose outside YAML."
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=body)))
    provider = GTFOBinsProvider(tmp_path, client=client)
    raw, data = provider.fetch_entry(NEW, "_gtfobins/printf")
    assert raw == body and data["functions"]["shell"][0]["code"] == "printf '---'"


def test_driver_cache_excludes_pe_metadata_and_oversize_download_keeps_prior_cache(
    tmp_path: Path,
) -> None:
    source = [{"Id": "one", "KnownVulnerableSamples": [{"SHA256": "a" * 64, "PE": "x" * 1024}]}]
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=source)))
    provider = LolDriversProvider(tmp_path, client=client)
    matches = provider.enrich("a" * 64)
    assert matches and "PE" not in matches[0]["entry"]["KnownVulnerableSamples"][0]
    cache = tmp_path / ".hecate/catalogs/loldrivers.json"
    previous = cache.read_text()
    assert "PE" not in previous
    import os

    os.utime(cache, (0, 0))
    provider.max_catalog_bytes = 20
    with pytest.raises(ValueError, match="exceeds size limit"):
        provider.enrich("a" * 64)
    assert cache.read_text() == previous


def test_catalog_shell_chains_do_not_require_shell_separators_in_child_process_telemetry() -> None:
    from hecate_runner.cti.reference_rules import shell_segments

    command = r"sc.exe create vulnerable binPath=C:\Windows\Temp\driver.sys type=kernel && sc.exe start vulnerable"
    candidates = reference_candidates(
        {
            "evidence_profile": "behavior_catalog",
            "platform": "Windows",
            "source_artifacts": [{"kind": "command_line", "value": command}],
        }
    )
    assert len(candidates) == 2
    assert all("&&" not in c["detection"]["selection"]["CommandLine|contains"] for c in candidates)
    assert "type=kernel" in candidates[0]["detection"]["selection"]["CommandLine|contains"]
    assert shell_segments('bash -c "echo a && echo b" && bash -p') == [
        'bash -c "echo a && echo b"',
        "bash -p",
    ]
