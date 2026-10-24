"""Rule review through a cycle (deep-dive appendix A2)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import SigmaResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

REVIEWED = """title: cmd.exe launched by a resume executable
logsource: {category: process_creation}
detection:
  selection: {Image|endswith: '\\\\cmd.exe'}
  condition: selection
hecate_review: {verdict: revise, issues: [no parent constraint]}
"""


def _run(settings: Settings, hecate: MagicMock, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    hecate.sigma_generator.return_value = SigmaResult(
        success=True,
        rules=[
            {
                "logsource_category": "process_creation",
                "title": "cmd.exe launched by a resume executable",
                "filename": "r.yml",
                "rule_yaml": REVIEWED,
            }
        ],
        review_gaps=[{"behaviour": "decoy opened in Word", "quote": "opening a DOCX in Word"}],
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="OTX Pulse: VShell\nDescription: a resume loader.", source="otx"
    )
    result = Orchestrator(settings=settings, hecate=hecate, cti_provider=provider).run_once()
    trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
    return result.draft_path.read_text(), trail


def test_review_is_requested_and_logged(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    _, trail = _run(settings, mock_hecate, caplog)
    assert mock_hecate.sigma_generator.call_args.args[0]["review_rules"] is True
    assert any(
        "1 model rule(s) reviewed (cmd.exe launched by a resume executable: revise); "
        "1 uncovered behaviour(s): decoy opened in Word" in m
        for m in trail
    )


def test_the_draft_lists_what_no_rule_covers(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    draft, _ = _run(settings, mock_hecate, caplog)
    section = draft.split("#### Not Covered by Any Rule (rule review)", 1)[1]
    assert '- decoy opened in Word: "opening a DOCX in Word"' in section


def test_pass2_generates_targeted_rule_for_uncovered_command(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture, tmp_path
) -> None:
    caplog.set_level(logging.INFO)
    mock_hecate.sigma_generator.return_value = SigmaResult(
        success=True,
        rules=[
            {
                "logsource_category": "process_creation",
                "title": "Existing Windows Rule",
                "filename": "existing.yml",
                "rule_yaml": REVIEWED,
            }
        ],
        review_gaps=[
            {
                "behaviour": "container escape and namespace switch",
                "quote": "nsenter -t 1 -m -u -i -n -p /bin/bash",
            }
        ],
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="OTX Pulse: VShell\nDescription: a resume loader.",
        source="otx",
    )
    result = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()
    assert result.draft_path.exists()
    trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
    assert any("pass 2: generated 1 rule(s) for uncovered behaviors" in m for m in trail)

    # Verify pass 2 rule written to disk in queries/
    query_dir = settings.hecate_workspace / "queries" / result.hunt_id
    pass2_files = list(query_dir.glob("*nsenter*.yml"))
    assert len(pass2_files) == 1
    content = pass2_files[0].read_text()
    import yaml

    doc = yaml.safe_load(content)
    assert doc["logsource"] == {"category": "process_creation", "product": "linux"}
    assert doc["detection"]["selection"]["Image|endswith"] == "/nsenter"


def test_pass2_generates_targeted_rule_for_uncovered_file_path(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    mock_hecate.sigma_generator.return_value = SigmaResult(
        success=True,
        rules=[
            {
                "logsource_category": "process_creation",
                "title": "Existing Windows Rule",
                "filename": "existing.yml",
                "rule_yaml": REVIEWED,
            }
        ],
        review_gaps=[
            {
                "behaviour": "Creation of a rogue cron job for persistence",
                "quote": "echo '* * * * * root /usr/local/bin/agent' > /etc/cron.d/kworker_audit",
            }
        ],
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="OTX Pulse: VShell\nDescription: a resume loader with /etc/cron.d/kworker_audit persistence.",
        source="otx",
    )
    result = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()
    assert result.draft_path.exists()

    query_dir = settings.hecate_workspace / "queries" / result.hunt_id
    pass2_files = list(query_dir.glob("*file_event*.yml"))
    assert len(pass2_files) >= 1
    cron_files = [f for f in pass2_files if "kworker_audit" in f.name]
    assert len(cron_files) == 1
    content = cron_files[0].read_text()
    import yaml

    doc = yaml.safe_load(content)
    assert doc["logsource"] == {"category": "file_event", "product": "linux"}
    assert "/etc/cron.d/kworker_audit" in doc["detection"]["selection"]["TargetFilename|contains"]
