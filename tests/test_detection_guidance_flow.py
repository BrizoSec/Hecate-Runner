"""The source's detection guidance through a cycle (deep-dive item #8)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest
from hecate_agent.core.source_evidence import SourceArtifact, SourceEvidence

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import SigmaResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

REPORT = "https://report.example/vshell"

ITEM = CTIItem(
    content=(
        "OTX Pulse: A fake resume installed VShell\n"
        "Description: A resume executable launches cmd.exe and a VShell RAT.\n"
        f"References: {REPORT}"
    ),
    source="otx",
    title="A fake resume installed VShell",
)

PAGE = (
    "The resume executable launches cmd.exe.\n"
    "detection and hunting\n"
    "endpoint\n"
    "Hunt for:\n"
    "%TEMP%\\log_de.log\n"
    "Resume-themed executables launching\ncmd.exe\nand then Word\n"
    "AllocADsMem\nfollowed by\nVirtualProtect\n"
    "iocs\n"
)


@pytest.fixture
def guided(mock_hecate: MagicMock) -> MagicMock:
    mock_hecate.source_evidence.side_effect = None
    mock_hecate.source_evidence.return_value = SourceEvidence(
        url=REPORT,
        chars=len(PAGE),
        chunks=1,
        text=PAGE,
        artifacts=[
            SourceArtifact(
                "cmd.exe",
                "process",
                "spawned shell",
                "active",
                "unknown",
                "The resume executable launches cmd.exe.",
            )
        ],
    )
    mock_hecate.sigma_generator.return_value = SigmaResult(
        success=True,
        rules=[
            {
                "logsource_category": "process_creation",
                "title": "Source guidance G2: cmd.exe launching winword.exe",
                "filename": "process_creation__guidance.yml",
                "rule_yaml": "title: x\n",
                "techniques": [],
                "level": "medium",
            }
        ],
    )
    return mock_hecate


def _run(settings: Settings, hecate: MagicMock, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    provider = MagicMock()
    provider.next_item.return_value = ITEM
    return Orchestrator(settings=settings, hecate=hecate, cti_provider=provider).run_once()


def test_the_guidance_reaches_sigma_drafting(
    settings: Settings, guided: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    _run(settings, guided, caplog)
    payload = guided.sigma_generator.call_args.args[0]
    routes = {g["text"]: g["route"] for g in payload["detection_guidance"]}
    assert routes == {
        "%TEMP%\\log_de.log": "sigma",
        "Resume-themed executables launching cmd.exe and then Word": "sigma",
        "AllocADsMem followed by VirtualProtect": "edr",
    }


def test_the_draft_lists_each_item_with_where_it_runs(
    settings: Settings, guided: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    draft = _run(settings, guided, caplog).draft_path.read_text()
    section = draft.split("### Detection Guidance from the Source", 1)[1].split(
        "### Hunting Queries", 1
    )[0]
    assert f"Quoted from the detection section of {REPORT}." in section
    assert (
        '| G2 | "Resume-themed executables launching cmd.exe and then Word" | Sigma | '
        "cmd.exe launching winword.exe |" in section
    )
    assert '| G1 | "%TEMP%\\log_de.log" | Sigma | no rule drafted; write one by hand |' in section
    assert '| G3 | "AllocADsMem followed by VirtualProtect" | EDR query |' in section


def test_the_trail_counts_the_guidance(
    settings: Settings, guided: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    _run(settings, guided, caplog)
    trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
    assert any(
        "3 item(s) from the source: 1 edr, 2 sigma; 3 Sigma candidate(s)" in m for m in trail
    )


def test_a_source_without_guidance_says_so(
    settings: Settings, guided: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    guided.source_evidence.return_value.text = "The resume executable launches cmd.exe.\n"
    draft = _run(settings, guided, caplog).draft_path.read_text()
    trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
    assert any("publishes no detection guidance section" in m for m in trail)
    assert "### Detection Guidance from the Source" not in draft
