"""Publisher auto-merge must agree with the deterministic human-review gate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from hecate_runner.config import Settings
from hecate_runner.github_publisher import (
    GitHubAppClient,
    PublisherError,
    _snapshot_bundle,
    enqueue_hunt,
    outbox_for,
)
from hecate_runner.promotion_policy import load_policy


def _bundle_workspace(tmp_path: Path, *, unsupported: bool) -> Settings:
    workspace = tmp_path / "workspace"
    (workspace / "hunts/2026/Q4").mkdir(parents=True)
    (workspace / "queries/H-9001").mkdir(parents=True)
    (workspace / "research").mkdir()
    policy = {
        "version": 1,
        "target_visibility": "private",
        "publisher_login": "hecate-publisher[bot]",
        "auto_merge": {"enabled": True, "merge_method": "squash"},
        "review": {"minimum_approvals": 1, "allowed_associations": ["OWNER"]},
        "risk": {
            "missing_cti": "review",
            "missing_research": "review",
            "missing_sigma": "review",
            "incomplete_metadata": "review",
            "low_confidence_source": "review",
            "unsupported_claims": "review",
            "tlp_amber": "review",
            "unknown_tlp": "allow_private",
        },
    }
    (workspace / "promotion-policy.yaml").write_text(yaml.safe_dump(policy))
    value = "not-in-source.example" if unsupported else "source.example"
    body = f"""---
hunt_id: H-9001
status: planning
techniques: [T1059.003]
platform: [Windows]
data_sources: [process_creation]
spawned_from: R-9001
---
# H-9001
### Threat Context
Source CTI:
> Report names source.example.
### Justification
Investigate activity to {value}.
```yaml
title: Test destination
logsource:
  category: network_connection
detection:
  selection:
    DestinationHostname: {value}
  condition: selection
```
### Grounding
| Claim | Type | Grounding |
|---|---|---|
| `{value}` | indicator | inferred |
"""
    (workspace / "hunts/2026/Q4/H-9001.md").write_text(body)
    (workspace / "research/R-9001.md").write_text("research")
    (workspace / "queries/H-9001/rule.yml").write_text(
        "title: Test\nid: 3c9bd7e9-522b-46e1-86c1-85bcf5d971a2\n"
        "logsource:\n  category: process_creation\n"
        "detection:\n  selection:\n    Image|endswith: test.exe\n  condition: selection\n"
    )
    return Settings(_env_file=None, hecate_workspace=workspace)  # type: ignore[call-arg]


def test_review_classified_hunt_is_never_snapshotted_for_auto_merge(tmp_path: Path) -> None:
    settings = _bundle_workspace(tmp_path, unsupported=True)
    files, _ = _snapshot_bundle(settings, "H-9001")
    manifest = json.loads(next(v for k, v in files.items() if k.startswith("promotion-manifests/")))
    assert manifest["auto_merge"] is False
    assert manifest["review_required"] is True
    assert any("unsupported claim" in reason for reason in manifest["promotion_reasons"])


def test_eligible_hunt_keeps_policy_auto_merge_enabled(tmp_path: Path) -> None:
    settings = _bundle_workspace(tmp_path, unsupported=False)
    files, _ = _snapshot_bundle(settings, "H-9001")
    manifest = json.loads(next(v for k, v in files.items() if k.startswith("promotion-manifests/")))
    assert manifest["auto_merge"] is True
    assert manifest["review_required"] is False


def test_auto_merge_api_failure_never_falls_back_to_direct_merge(monkeypatch) -> None:
    client = object.__new__(GitHubAppClient)
    calls: list[tuple[str, str]] = []

    def request(method: str, path: str, **kwargs):
        calls.append((method, path))
        return {"errors": [{"message": "Auto merge is not allowed for this repository"}]}

    monkeypatch.setattr(client, "_request", request)
    merged = client._set_auto_merge(
        "BrizoSec/Hecate-Content",
        {"number": 70, "node_id": "PR_node"},
        enabled=True,
        merge_method="squash",
    )

    assert merged is False
    assert calls == [("POST", "/graphql")]


def _public_settings(tmp_path: Path) -> Settings:
    settings = _bundle_workspace(tmp_path, unsupported=False)
    policy_path = settings.hecate_workspace / "promotion-policy.yaml"
    policy = yaml.safe_load(policy_path.read_text())
    policy["target_visibility"] = "public"
    policy["risk"]["unknown_tlp"] = "allow"
    policy["risk"]["tlp_amber"] = "block"
    destination = tmp_path / "public-repo"
    destination.mkdir()
    settings.github_publishing_policy_path = destination / "promotion-policy.yaml"
    settings.github_publishing_policy_path.write_text(yaml.safe_dump(policy))
    settings.github_publishing_repository = "example/Hecate-Public"
    settings.github_publishing_outbox_path = tmp_path / "public-outbox.sqlite3"
    return settings


def test_public_policy_uses_destination_config_and_a_fresh_queue(tmp_path: Path) -> None:
    settings = _public_settings(tmp_path)
    old_settings = settings.model_copy(
        update={"github_publishing_outbox_path": None, "github_publishing_policy_path": None}
    )
    enqueue_hunt(old_settings, "H-9001")
    assert outbox_for(old_settings).has_due()
    assert not outbox_for(settings).has_due()
    enqueue_hunt(settings, "H-9001")
    row = outbox_for(settings).claim_due()
    files = json.loads(row["payload"])
    manifest = json.loads(next(v for k, v in files.items() if k.startswith("promotion-manifests/")))
    assert manifest["target_visibility"] == "public"
    assert manifest["target_repository"] == "example/Hecate-Public"
    assert outbox_for(old_settings).has_due()


@pytest.mark.parametrize("tlp", ["GREEN", "AMBER", "AMBER+STRICT", "RED"])
@pytest.mark.parametrize("artifact", ["hunt", "research", "query"])
def test_public_snapshot_rejects_restricted_material_in_every_artifact(
    tmp_path: Path, tlp: str, artifact: str
) -> None:
    settings = _public_settings(tmp_path)
    path = (
        settings.hecate_workspace
        / {
            "hunt": "hunts/2026/Q4/H-9001.md",
            "research": "research/R-9001.md",
            "query": "queries/H-9001/rule.yml",
        }[artifact]
    )
    path.write_text(path.read_text() + f"\n# TLP:{tlp}\n")
    with pytest.raises((PublisherError, ValueError), match="public"):
        enqueue_hunt(settings, "H-9001")
    assert not outbox_for(settings).has_due()


@pytest.mark.parametrize("secret", ["ghp_" + "a" * 36, "runtime-api-key-1234567890"])
def test_credentials_are_blocked_before_public_queueing(tmp_path: Path, secret: str) -> None:
    settings = _public_settings(tmp_path)
    settings.misp_api_key = "runtime-api-key-1234567890"
    path = settings.hecate_workspace / "research/R-9001.md"
    path.write_text(secret)
    with pytest.raises(PublisherError, match="Credential material") as error:
        enqueue_hunt(settings, "H-9001")
    assert secret not in str(error.value)


@pytest.mark.parametrize("change", ["private-risk", "amber-review"])
def test_public_policy_rejects_private_only_risk_actions(tmp_path: Path, change: str) -> None:
    settings = _public_settings(tmp_path)
    path = settings.github_publishing_policy_path
    policy = yaml.safe_load(path.read_text())
    policy["risk"]["unknown_tlp" if change == "private-risk" else "tlp_amber"] = (
        "allow_private" if change == "private-risk" else "review"
    )
    path.write_text(yaml.safe_dump(policy))
    with pytest.raises(ValueError, match="public publication"):
        load_policy(settings.hecate_workspace, path)


@pytest.mark.parametrize("mismatch", ["repository", "visibility", "restricted-retry"])
def test_retargeted_or_restricted_outbox_never_reaches_github(
    tmp_path: Path, monkeypatch, mismatch: str
) -> None:
    settings = _public_settings(tmp_path)
    if mismatch == "visibility":
        private = settings.model_copy(update={"github_publishing_policy_path": None})
        enqueue_hunt(private, "H-9001")
    else:
        enqueue_hunt(settings, "H-9001")
    row = dict(outbox_for(settings).claim_due())
    if mismatch == "repository":
        settings.github_publishing_repository = "example/different-repo"
    elif mismatch == "restricted-retry":
        files = json.loads(row["payload"])
        files["research/R-9001.md"] += "\nTLP:GREEN\n"
        row["payload"] = json.dumps(files)
    client = object.__new__(GitHubAppClient)
    client.settings = settings
    calls = []
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(PublisherError):
        client.publish(row)
    assert calls == []


def test_public_publisher_creates_an_isolated_pr_without_direct_merge(
    tmp_path: Path, monkeypatch
) -> None:
    settings = _public_settings(tmp_path)
    enqueue_hunt(settings, "H-9001")
    row = outbox_for(settings).claim_due()
    client = object.__new__(GitHubAppClient)
    client.settings = settings
    calls = []
    repo = "/repos/example/Hecate-Public"

    def request(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        if path == repo:
            return {"private": False}
        if "/pulls?" in path:
            return []
        if "/git/ref/heads/hecate/" in path:
            raise PublisherError("HTTP 404")
        if path.endswith("/git/ref/heads/main"):
            return {"object": {"sha": "base"}}
        if path.endswith("/git/commits/base"):
            return {"tree": {"sha": "base-tree"}}
        if path.endswith(("/git/trees", "/git/commits", "/git/refs")):
            return {"sha": "new-object"}
        if path.endswith("/pulls"):
            return {"number": 1, "node_id": "PR_1", "html_url": "https://example.test/pull/1"}
        if path == "/graphql":
            return {"data": {}}
        raise AssertionError((method, path))

    monkeypatch.setattr(client, "_request", request)
    result = client.publish(row)
    assert result.status == "published" and result.pr_number == 1
    assert any(method == "POST" and path == repo + "/pulls" for method, path, _ in calls)
    assert not any(path.endswith("/merge") for _, path, _ in calls)


def test_private_policy_blocks_an_unexpected_public_repository(tmp_path: Path, monkeypatch) -> None:
    settings = _bundle_workspace(tmp_path, unsupported=False)
    enqueue_hunt(settings, "H-9001")
    row = outbox_for(settings).claim_due()
    client = object.__new__(GitHubAppClient)
    client.settings = settings
    calls = []

    def request(method, path, **kwargs):
        calls.append(method)
        return {"private": False}

    monkeypatch.setattr(client, "_request", request)
    with pytest.raises(PublisherError, match="visibility"):
        client.publish(row)
    assert calls == ["GET"]
