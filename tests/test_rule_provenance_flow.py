"""Every indicator in a drafted rule traced to its source (deep-dive item #11)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import SigmaResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

LOADER = "81c51138d5527ca7dcc258171eb36659c479f66c86a8947b6340d040b3860a30"

TRACED = f"""title: Execution of a file hash named in the source intelligence
logsource: {{category: process_creation}}
detection:
  selection:
    Hashes|contains: ['SHA256={LOADER}']
  condition: selection
hecate_provenance:
- {{value: {LOADER}, type: sha256, role: executable, source: 'https://report.example/vshell'}}
"""
UNTRACED = """title: Connection to the C2
logsource: {category: network_connection}
detection:
  selection:
    DestinationIp: 198.18.7.7
  condition: selection
"""


def _run(
    settings: Settings, hecate: MagicMock, caplog: pytest.LogCaptureFixture, *rules: str
) -> list[str]:
    caplog.set_level(logging.INFO)
    hecate.sigma_generator.return_value = SigmaResult(
        success=True,
        rules=[
            {
                "logsource_category": "x",
                "title": f"rule {i}",
                "filename": f"r{i}.yml",
                "rule_yaml": text,
            }
            for i, text in enumerate(rules)
        ],
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="OTX Pulse: VShell\nDescription: a resume loader.", source="otx"
    )
    Orchestrator(settings=settings, hecate=hecate, cti_provider=provider).run_once()
    return [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]


def test_traced_indicators_are_counted(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    trail = _run(settings, mock_hecate, caplog, TRACED)
    assert any("1 indicator(s) across 1 rule(s), each traced to its source" in m for m in trail)


def test_an_untraced_address_is_named(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    trail = _run(settings, mock_hecate, caplog, TRACED, UNTRACED)
    assert any("untraced indicator(s) in rules: 198.18.7.7 (rule 1)" in m for m in trail)
    assert any(
        r.levelname == "WARNING" and "no provenance: 198.18.7.7" in r.getMessage()
        for r in caplog.records
    )
