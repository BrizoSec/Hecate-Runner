"""Tests for the permanent purple-team validation harness in Hecate Runner."""
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

from hecate_runner.config import Settings
from hecate_runner.hunt_writer import DraftHuntRequest
from hecate_runner.orchestrator import Orchestrator


def test_purple_team_validation_runs_and_tunes_rules(tmp_path: Path) -> None:
    settings = Settings(hecate_workspace=tmp_path)
    orch = Orchestrator(settings=settings, hecate=MagicMock(), cti_provider=MagicMock())
    orch.trail = MagicMock()
    orch.trail.elapsed = 1.0

    mock_hypothesis = MagicMock()
    mock_hypothesis.techniques = ["T1053.003", "T1059.004"]
    mock_hypothesis.is_indicator_only = False

    req = DraftHuntRequest(
        hunt_id="H-9999",
        threat_intel="Test threat intelligence",
        hypothesis=mock_hypothesis,
        generated_at=datetime.now(UTC),
    )

    out_dir = tmp_path / "queries" / "H-9999"
    out_dir.mkdir(parents=True)

    rule_file = out_dir / "process_creation__test_cron.yml"
    rule_content = """title: Suspicious Cron Execution
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: /etc/cron.d
  condition: selection
"""
    rule_file.write_text(rule_content, encoding="utf-8")

    rule_dict: dict[str, object] = {
        "filename": "process_creation__test_cron",
        "logsource_category": "process_creation",
        "title": "Suspicious Cron Execution",
        "rule_yaml": rule_content,
    }
    rules = [rule_dict]

    item = MagicMock()
    item.indicators = []

    # Run the purple team validation
    orch._run_purple_team_validation(req, rules, out_dir, item)

    # Verify that the rule was evaluated and purple_team metadata was attached
    pt_meta = rules[0].get("purple_team")
    assert isinstance(pt_meta, dict)
    assert pt_meta["validated"] is True
    assert "precision" in pt_meta
    assert "recall" in pt_meta

    # Verify that trail logged the purple team stage
    orch.trail.step.assert_called_once()
    assert orch.trail.step.call_args[0][0] == "purple_team"
