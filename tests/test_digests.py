"""Unit tests for the specialized daily digests metrics collectors."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.config import Settings
from hecate_runner.digests import (
    collect_detection_engineering_metrics,
    collect_threat_hunting_metrics,
    collect_threat_intel_metrics,
)


def test_collect_detection_engineering_metrics(settings: Settings, tmp_path: Path) -> None:
    ws = tmp_path / "fake-hecate"
    queries_dir = ws / "queries" / "H-0001"
    queries_dir.mkdir(parents=True)
    rule_file = queries_dir / "audit__suspicious_process.yml"
    rule_file.write_text("title: Suspicious Process Creation\ntags:\n  - attack.t1059.001\n")

    hunts_dir = ws / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0001.md"
    hunt_file.write_text(
        "---\n"
        "hunt_id: H-0001\n"
        "title: Suspicious Process Hunt\n"
        "status: planning\n"
        "tactics: [execution]\n"
        "techniques: [T1059.001]\n"
        "purple_team_rules_evaluated: 5\n"
        "purple_team_rules_validated: 4\n"
        "---\n# Body\n"
    )

    settings = settings.model_copy(update={"hecate_workspace": ws})
    metrics = collect_detection_engineering_metrics(settings, hours=24)

    assert metrics["total_sigma_rules"] >= 1
    assert metrics["recent_hunts_count"] == 1
    assert metrics["rules_evaluated_24h"] == 5
    assert metrics["rules_validated_24h"] == 4
    assert metrics["pass_rate_pct"] == "80.0%"
    assert "Execution" in metrics["top_tactics"]
    assert len(metrics["recent_rules"]) >= 1


def test_collect_threat_intel_metrics(settings: Settings, tmp_path: Path) -> None:
    ws = tmp_path / "fake-hecate"
    research_dir = ws / "research"
    research_dir.mkdir(parents=True)
    res_file = research_dir / "R-0001.md"
    res_file.write_text(
        "---\n"
        "research_id: R-0001\n"
        'topic: "Title: High Severity Vulnerability"\n'
        "estimated_hunt_complexity: high\n"
        "---\n"
        "Adversaries exploit CVE-2024-9999 actively.\n"
    )

    settings = settings.model_copy(update={"hecate_workspace": ws})
    metrics = collect_threat_intel_metrics(settings, hours=24)

    assert metrics["total_research_count"] == 1
    assert metrics["recent_research_count"] == 1
    assert metrics["cves_tracked_count"] == 1
    assert "CVE-2024-9999" in metrics["cves_sample"]
    assert len(metrics["recent_topics"]) == 1
    assert "High Severity Vulnerability" in metrics["recent_topics"][0]["topic"]


def test_collect_threat_hunting_metrics(settings: Settings, tmp_path: Path) -> None:
    ws = tmp_path / "fake-hecate"
    hunts_dir = ws / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0001.md"
    hunt_file.write_text(
        "---\n"
        "hunt_id: H-0001\n"
        "title: DRAFT - Test Campaign\n"
        "status: planning\n"
        "hunter: hecate-runner\n"
        "---\n# Body\n"
    )

    logs_dir = ws / "logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / "stage_metrics.jsonl").write_text("")

    settings = settings.model_copy(update={"hecate_workspace": ws})
    metrics = collect_threat_hunting_metrics(settings, hours=24)

    assert metrics["total_hunts"] == 1
    assert metrics["recent_hunts_count"] == 1
    assert metrics["status_counts"]["planning"] == 1
    assert len(metrics["hunt_spotlights"]) == 1
    assert metrics["hunt_spotlights"][0]["id"] == "H-0001"
