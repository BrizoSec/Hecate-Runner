"""Observable and claim audit through a cycle (deep-dive item #7)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

ITEM = CTIItem(
    content="OTX Pulse: VShell via fake resume\nDescription: A resume executable launches cmd.exe and a VShell RAT.",
    source="otx",
    title="VShell via fake resume",
)


@pytest.fixture
def draft(settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture) -> str:
    caplog.set_level(logging.INFO)
    mock_hecate.candidate_techniques.return_value = [("T1059.003", "Windows Command Shell")]
    mock_hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="Adversaries deliver VShell through a fake resume",
        justification="The RAT enables persistent, stealthy access to research networks.",
        behavior="Resume executable launches cmd.exe",
        techniques=["T1059.003"],
        data_sources=["process_execution"],
        observables=["process.name: memfd_create", "cmd.exe spawned by a resume-named executable"],
        false_positives=[
            "Internal transfers of files with similar SHA256 hashes",
            "HR staff opening resumes",
        ],
    )
    provider = MagicMock()
    provider.next_item.return_value = ITEM
    return (
        Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)
        .run_once()
        .draft_path.read_text()
    )


def _section(draft: str, heading: str) -> str:
    return draft.split(heading, 1)[1].split("\n### ", 1)[0]


def test_unobservable_entries_are_removed_from_the_draft(draft: str) -> None:
    assert "cmd.exe spawned by a resume-named executable" in _section(
        draft, "### What Suspicious Looks Like"
    )
    assert "memfd_create" not in _section(draft, "### What Suspicious Looks Like")
    assert "HR staff opening resumes" in _section(draft, "### What Normal Looks Like")
    assert "similar SHA256" not in _section(draft, "### What Normal Looks Like")


def test_capability_stated_as_fact_is_softened(draft: str) -> None:
    assert "could enable persistent (capability; not observed in the source)" in _section(
        draft, "### Justification"
    )


def test_every_audit_action_is_recorded_under_grounding(
    draft: str, caplog: pytest.LogCaptureFixture
) -> None:
    audit = _section(draft, "### Grounding").split("#### Claim Audit", 1)[1]
    assert '- removed (observables): "process.name: memfd_create"' in audit
    assert (
        '- removed (normal baseline): "Internal transfers of files with similar SHA256 hashes"'
        in audit
    )
    assert '- softened (justification): "enables persistent"' in audit
    # The cycle ran in the fixture, so its trail was logged during setup.
    trail = [r.getMessage() for r in caplog.get_records("setup") if r.name == LOGGER_NAME]
    assert any("audit: 2 removed, 1 softened" in m for m in trail)


def test_the_empty_observables_sentinel_is_not_an_audit_finding(
    settings: Settings, mock_hecate: MagicMock
) -> None:
    mock_hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="x", techniques=["T1059.003"], observables=["process_execution"]
    )
    provider = MagicMock()
    provider.next_item.return_value = ITEM
    draft = (
        Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)
        .run_once()
        .draft_path.read_text()
    )
    assert "[none proposed - human to populate]" in _section(
        draft, "### What Suspicious Looks Like"
    )
    assert "#### Claim Audit" not in draft
