"""Publisher auto-merge must agree with the deterministic human-review gate."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from hecate_runner.config import Settings
from hecate_runner.github_publisher import GitHubAppClient, _snapshot_bundle


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
