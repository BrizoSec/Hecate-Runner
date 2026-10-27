"""Tests for Orchestrator BAS validation flow and Hunt Writer rendering."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.orchestrator import Orchestrator


def test_render_draft_with_bas_verification() -> None:
    req = DraftHuntRequest(
        hunt_id="H-0099",
        generated_at=datetime(2026, 10, 27, 12, 0, tzinfo=UTC),
        hypothesis=HypothesisResult(
            hypothesis="Adversaries execute commands via PowerShell",
            techniques=["T1059.001"],
            data_sources=["process_creation"],
        ),
        tactics=["execution"],
        platforms=["windows"],
        threat_intel="Adversary PowerShell execution detected.",
        bas_verification={
            "status": "verified_true_positive",
            "provider": "mock",
            "technique_id": "T1059.001",
            "ability_id": "ability-powershell-test",
            "telemetry_arrived": True,
            "rule_triggered": True,
            "matched_events_count": 1,
            "duration_seconds": 0.45,
            "notes": ["Sigma AST evaluator matched 1 true positive event(s)."],
        },
    )

    rendered = render_draft(req)

    # Frontmatter assertions
    assert "bas_verified: true" in rendered
    assert 'bas_provider: "mock"' in rendered
    assert 'bas_status: "verified_true_positive"' in rendered
    assert "bas_detection_triggered: true" in rendered

    # Body assertions
    assert "### Live Adversary Emulation & Breach Simulation (BAS)" in rendered
    assert "VERIFIED TRUE POSITIVE" in rendered
    assert "- **Provider:** `MOCK`" in rendered
    assert "- **Target Technique:** `T1059.001` (ability-powershell-test)" in rendered
    assert "- **Telemetry Observed:** Yes" in rendered
    assert "- **Detection Triggered:** Yes (1 hit(s))" in rendered


def test_orchestrator_run_bas_validation(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "hunts").mkdir(parents=True)
    out_dir = workspace / "queries" / "H-0099"
    out_dir.mkdir(parents=True)

    settings = Settings(
        hecate_workspace=workspace,
        hunts_root=workspace / "hunts",
        bas_enabled=True,
        bas_mode="mock",
        bas_allowed_hosts=["lab-host"],
        bas_windows_host="lab-host",
    )

    hecate_client = MagicMock()
    cti_provider = MagicMock()
    orchestrator = Orchestrator(settings=settings, hecate=hecate_client, cti_provider=cti_provider)

    req = DraftHuntRequest(
        hunt_id="H-0099",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(
            hypothesis="PowerShell download cradle",
            techniques=["T1059.001"],
        ),
        platforms=["windows"],
        threat_intel="Adversary execution detected in report.",
    )

    rules = [
        {
            "title": "PowerShell Download Cradle",
            "techniques": ["T1059.001"],
            "logsource_category": "process_creation",
            "rule_yaml": """title: PowerShell Download Cradle
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
""",
        }
    ]

    item = CTIItem(
        source="unit_test",
        title="Test CTI",
        source_url="https://example.com/cti",
        content="Adversary execution",
    )

    orchestrator._run_bas_validation(req, rules, out_dir, item)

    assert req.bas_verification is not None
    assert req.bas_verification["status"] == "verified_true_positive"
    assert req.bas_verification["provider"] == "mock"
    assert req.bas_verification["telemetry_arrived"] is True
    assert req.bas_verification["rule_triggered"] is True

    # Trail / Log assertion
    assert "BAS validation completed for H-0099" in caplog.text


def test_orchestrator_requires_separate_opt_in_for_unattended_live_bas(tmp_path, monkeypatch):
    settings = Settings(
        hecate_workspace=tmp_path,
        hunts_root=tmp_path / "hunts",
        bas_enabled=True,
        bas_auto_execute_live=False,
    )
    provider = MagicMock(name="provider")
    provider.name = "caldera"
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)
    orchestrator = Orchestrator(settings=settings, hecate=MagicMock(), cti_provider=MagicMock())
    orchestrator._run_bas_validation(MagicMock(), [{}], tmp_path, MagicMock())
    provider.detonate.assert_not_called()
