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
