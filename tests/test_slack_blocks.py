"""Unit tests for Slack Block Kit message builders."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.cti.base import CTIItem
from hecate_runner.orchestrator import RunResult
from hecate_runner.slack_blocks import (
    COLOR_CRITICAL,
    COLOR_INFO,
    COLOR_PURPLE,
    COLOR_SUCCESS,
    COLOR_WARNING,
    build_detection_engineering_digest_card,
    build_draft_card,
    build_hunt_completed_card,
    build_ops_metrics_card,
    build_purple_team_card,
    build_threat_hunting_digest_card,
    build_threat_intake_card,
    build_threat_intel_digest_card,
    defang_ioc,
)


def test_build_draft_card() -> None:
    result = RunResult(
        outcome="draft_created",
        hunt_id="H-0854",
        draft_path=Path("/workspace/hunts/2026/Q4/H-0854.md"),
        research_id="R-0012",
        parked_count=2,
    )
    cards = build_draft_card(result)
    assert len(cards) == 1
    assert cards[0]["color"] == COLOR_WARNING

    blocks = cards[0]["blocks"]
    assert blocks[0]["type"] == "header"
    assert "H-0854" in blocks[0]["text"]["text"]

    section_text = blocks[1]["text"]["text"]
    assert "H-0854" in section_text
    assert "R-0012" in section_text

    fields = blocks[2]["fields"]
    assert "planning" in fields[0]["text"]
    assert "2 commentary item(s) parked" in fields[1]["text"]


def test_build_hunt_completed_card() -> None:
    cards = build_hunt_completed_card(
        hunt_id="H-0852",
        topic="VulnCheck/MSRC CLFS CVE-2024-30088 LPE",
        techniques=["T1068", "T1190"],
        sigma_count=11,
        pr_url="https://github.com/BrizoSec/Hecate-Content/pull/31",
        misp_event_id="140",
    )
    assert len(cards) == 1
    assert cards[0]["color"] == COLOR_SUCCESS

    blocks = cards[0]["blocks"]
    assert blocks[0]["type"] == "header"
    assert "H-0852" in blocks[0]["text"]["text"]

    # Action buttons
    action_block = next((b for b in blocks if b["type"] == "actions"), None)
    assert action_block is not None
    button_urls = [btn["url"] for btn in action_block["elements"]]
    assert "https://github.com/BrizoSec/Hecate-Content/pull/31" in button_urls
    assert "https://localhost:8443/events/view/140" in button_urls


def test_build_purple_team_card() -> None:
    # Success card
    cards_success = build_purple_team_card(
        hunt_id="H-0851",
        technique="T1071.001",
        success=True,
        telemetry_count=42,
        summary="C2 beacon matched Zeek HTTP logs",
        log_source="Zeek / Bro HTTP",
    )
    assert cards_success[0]["color"] == COLOR_SUCCESS
    assert "Detection Rule Verified" in cards_success[0]["blocks"][1]["fields"][1]["text"]

    # Telemetry gap card
    cards_gap = build_purple_team_card(
        hunt_id="H-0851",
        technique="T1059.001",
        success=False,
        telemetry_count=0,
        summary="No PowerShell ScriptBlock logs found",
    )
    assert cards_gap[0]["color"] == COLOR_WARNING
    assert "Telemetry / Coverage Gap" in cards_gap[0]["blocks"][1]["fields"][1]["text"]


def test_build_threat_intake_card() -> None:
    item = CTIItem(
        content="Active exploitation of CVE-2025-53770 with EPSS 100%.",
        source="first_org",
        received_at=datetime.now(UTC),
        identifier="first-org-cve-2025-53770",
        title="EPSS Spike: CVE-2025-53770",
        metadata={"evidence_profile": "vulnerability_advisory"},
        source_url="https://www.first.org/epss/",
    )
    cards = build_threat_intake_card(item)
    assert cards[0]["color"] == COLOR_CRITICAL
    assert "CVE-2025-53770" in cards[0]["blocks"][0]["text"]["text"]

    actions = next((b for b in cards[0]["blocks"] if b["type"] == "actions"), None)
    assert actions is not None
    assert actions["elements"][0]["url"] == "https://www.first.org/epss/"


def test_build_ops_metrics_card() -> None:
    summary = {
        "hunts_completed": 6,
        "sigma_rules_produced": 62,
        "spend_today_usd": 2.14,
        "daily_budget_usd": 20.0,
        "active_sources": ["first_org", "anyrun", "opencti", "vulncheck"],
        "purple_team_pass_pct": "100%",
    }
    cards = build_ops_metrics_card(summary)
    assert cards[0]["color"] == COLOR_INFO
    assert "Hecate 24-Hour Autonomous Ops Digest" in cards[0]["blocks"][0]["text"]["text"]

    fields = cards[0]["blocks"][1]["fields"]
    assert "6 hunts" in fields[0]["text"]
    assert "62 rules generated" in fields[1]["text"]
    assert "$2.14" in fields[3]["text"]


def test_build_detection_engineering_digest_card() -> None:
    data = {
        "total_sigma_rules": 695,
        "rules_validated_24h": 17,
        "rules_evaluated_24h": 28,
        "pass_rate_pct": "60.7%",
        "top_tactics": ["Persistence", "Privilege Escalation"],
        "platforms": ["AWS", "Windows"],
        "recent_rules": [
            {
                "title": "Suspicious AWS STS AssumeRole",
                "technique": "T1078.004",
                "file": "cloud_audit__sts.yml",
            }
        ],
    }
    cards = build_detection_engineering_digest_card(data)
    assert len(cards) == 1
    assert cards[0]["color"] == COLOR_SUCCESS
    assert "Daily Detection Engineering Digest" in cards[0]["blocks"][0]["text"]["text"]
    fields = cards[0]["blocks"][1]["fields"]
    assert "695 rules" in fields[0]["text"]
    assert "60.7%" in fields[1]["text"]


def test_build_threat_intel_digest_card() -> None:
    data = {
        "active_sources": ["otx", "cisa_kev", "first_org"],
        "total_sources_count": 3,
        "total_research_count": 313,
        "recent_research_count": 6,
        "cves_tracked_count": 14,
        "cves_sample": ["CVE-2024-21762"],
        "misp_sync_active": True,
        "recent_topics": [
            {
                "id": "R-0928",
                "topic": "Cloud Threat Intel: Multi-Cloud STS AssumeRole Hijacking",
                "complexity": "high",
            }
        ],
    }
    cards = build_threat_intel_digest_card(data)
    assert len(cards) == 1
    assert cards[0]["color"] == COLOR_CRITICAL
    assert "Daily Threat Intelligence Digest" in cards[0]["blocks"][0]["text"]["text"]
    fields = cards[0]["blocks"][1]["fields"]
    assert "Active Feeds (3)" in fields[0]["text"]
    assert "🟢 Connected & Syncing" in fields[1]["text"]


def test_build_threat_hunting_digest_card() -> None:
    data = {
        "total_hunts": 236,
        "recent_hunts_count": 4,
        "status_counts": {"planning": 4, "promoted": 0},
        "spend_today_usd": 1.50,
        "daily_budget_usd": 20.0,
        "budget_pct": "7.5%",
        "hunt_spotlights": [
            {
                "id": "H-0853",
                "title": "Adversaries use compromised AWS STS AssumeRole credentials",
                "status": "Planning",
                "hunter": "hecate-runner",
            }
        ],
    }
    cards = build_threat_hunting_digest_card(data)
    assert len(cards) == 1
    assert cards[0]["color"] == COLOR_PURPLE
    assert "Daily Threat Hunting Digest" in cards[0]["blocks"][0]["text"]["text"]
    fields = cards[0]["blocks"][1]["fields"]
    assert "4 runs" in fields[0]["text"]
    assert "$1.50" in fields[2]["text"]


def test_defang_ioc_neutralizes_malicious_indicators() -> None:
    sample = (
        "Adversary C2: https://kojur.ir/payload.exe on 185.220.101.5:8080.\n"
        "Contact: evil-actor@phish.xyz.\n"
        "Safe files: report.md and parser.py.\n"
        "Already defanged: evil[.]com and 10[.]0[.]0[.]1."
    )
    defanged = defang_ioc(sample)
    assert "https://" not in defanged
    assert "hxxps://" in defanged
    assert "kojur[.]ir" in defanged
    assert "185[.]220[.]101[.]5" in defanged
    assert "evil-actor[@]phish[.]xyz" in defanged
    # Preserves filenames and markdown extensions
    assert "report.md" in defanged
    assert "parser.py" in defanged
    # Idempotent (does not produce [[.]] or [[[.]])
    assert "evil[.]com" in defanged
    assert "[[.]]" not in defanged


def test_build_threat_intake_card_defangs_content() -> None:
    item = CTIItem(
        source="abuse_ch",
        title="ThreatFox Indicator: kojur.ir",
        identifier="1988783",
        content="Malware distribution server at https://kojur.ir/dl.php with IP 185.220.101.5",
        source_url="https://threatfox.abuse.ch/ioc/1988783/",
    )
    cards = build_threat_intake_card(item)
    header_text = cards[0]["blocks"][0]["text"]["text"]
    assert "kojur[.]ir" in header_text

    summary_text = cards[0]["blocks"][2]["text"]["text"]
    assert "hxxps://kojur[.]ir/dl.php" in summary_text
    assert "185[.]220[.]101[.]5" in summary_text
