"""Tests for BAS validation in promotion policy evaluation."""

from __future__ import annotations

from pathlib import Path

import yaml

from hecate_runner.promotion_policy import evaluate_promotion


def _setup_test_workspace(tmp_path: Path, bas_verified: bool, bas_status: str) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    queries_dir = workspace / "queries" / "H-0010"
    queries_dir.mkdir(parents=True)

    # Policy with bas_failed: review
    policy_content = {
        "version": 1,
        "target_visibility": "private",
        "publisher_login": "hecate-publisher[bot]",
        "auto_merge": {"enabled": True, "merge_method": "squash"},
        "review": {
            "minimum_approvals": 1,
            "allowed_associations": ["OWNER", "MEMBER"],
        },
        "risk": {
            "missing_cti": "review",
            "missing_research": "review",
            "missing_sigma": "review",
            "incomplete_metadata": "review",
            "low_confidence_source": "review",
            "unsupported_claims": "review",
            "tlp_amber": "review",
            "unknown_tlp": "allow_private",
            "bas_failed": "review",
        },
    }
    (workspace / "promotion-policy.yaml").write_text(
        yaml.safe_dump(policy_content), encoding="utf-8"
    )

    # Hunt file
    fm = {
        "hunt_id": "H-0010",
        "title": "Adversary T1059.001 PowerShell execution",
        "status": "planning",
        "date": "2026-10-27",
        "techniques": ["T1059.001"],
        "platform": ["windows"],
        "data_sources": ["process_creation"],
        "tags": ["draft", "auto-generated"],
        "bas_verified": bas_verified,
        "bas_provider": "caldera",
        "bas_status": bas_status,
        "bas_detection_triggered": bas_verified,
    }
    body = """# H-0010: Test Hunt

## LEARN: Prepare the Hunt

### Hypothesis Statement
Adversary uses PowerShell download cradles.

### Threat Context
Source CTI:
> CTI report detailing T1059.001 execution on endpoints.

### Justification
Test hunt justification.

### Threat Intel & Research
- Research Context: None
"""
    (hunts_dir / "H-0010.md").write_text(f"---\n{yaml.safe_dump(fm)}---\n{body}", encoding="utf-8")

    # Dummy query file so missing_sigma does not trigger
    (queries_dir / "rule.yml").write_text("title: Test Rule\n", encoding="utf-8")

    return workspace


def test_promotion_policy_blocks_on_bas_failure(tmp_path: Path) -> None:
    workspace = _setup_test_workspace(tmp_path, bas_verified=False, bas_status="detection_miss")
    decision = evaluate_promotion(workspace, "H-0010")

    assert decision.review_required is True
    assert decision.eligible is False
    assert any(
        "live adversary emulation verification failed (detection_miss)" in r
        for r in decision.reasons
    )


def test_promotion_policy_passes_on_bas_success(tmp_path: Path) -> None:
    workspace = _setup_test_workspace(
        tmp_path, bas_verified=True, bas_status="verified_true_positive"
    )
    decision = evaluate_promotion(workspace, "H-0010")

    assert not any("live adversary emulation verification failed" in r for r in decision.reasons)
