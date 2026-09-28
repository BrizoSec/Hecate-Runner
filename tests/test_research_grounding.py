"""Research grounding through a cycle: actual search counts, source-only marking, evidence limits."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult, ResearchResult, TechniqueMetadata
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

ITEM = CTIItem(
    content="OTX Pulse: VShell via fake resume\nDescription: A resume executable launches cmd.exe and a VShell RAT.",
    source="otx",
    title="VShell via fake resume",
)


def _run(settings: Settings, mock_hecate: MagicMock):
    provider = MagicMock()
    provider.next_item.return_value = ITEM
    return Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()


def _trail(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]


@pytest.fixture
def source_only(mock_hecate: MagicMock) -> MagicMock:
    mock_hecate.research_new.return_value = ResearchResult(
        research_id="R-0001", web_searches=0, web_search_note="no TAVILY_API_KEY configured"
    )
    return mock_hecate


@pytest.fixture
def independent(mock_hecate: MagicMock) -> MagicMock:
    mock_hecate.research_new.return_value = ResearchResult(research_id="R-0001", web_searches=3)
    return mock_hecate


def test_source_only_research_is_reported_and_warned(
    settings: Settings, source_only: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    result = _run(settings, source_only)
    trail = _trail(caplog)
    assert any(
        "grounding: source-only synthesis, 0 web searches: no TAVILY_API_KEY configured" in m
        for m in trail
    )
    assert any("SOURCE-ONLY" in m for m in trail)
    assert any(
        r.levelname == "WARNING" and "ran source-only" in r.getMessage() for r in caplog.records
    )
    assert result.outcome == "draft_created"  # warned, not parked
    assert (
        "(source-only synthesis, 0 web searches: no TAVILY_API_KEY configured)"
        in result.draft_path.read_text()
    )


def test_independent_research_reports_its_search_count(
    settings: Settings, independent: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    result = _run(settings, independent)
    trail = _trail(caplog)
    assert any("grounding: independent research, 3 web search(es)" in m for m in trail)
    assert not any("SOURCE-ONLY" in m for m in trail)
    assert "(independent research, 3 web search(es))" in result.draft_path.read_text()


def _research_only_technique(
    settings: Settings, hecate: MagicMock, sample_hypothesis: HypothesisResult
) -> str:
    """A model pick whose only support is the research document's wording."""
    research = settings.hecate_workspace / "research"
    research.mkdir(parents=True, exist_ok=True)
    (research / "R-0001.md").write_text(
        "VShell also offers screen capture to its operators.\n", encoding="utf-8"
    )
    sample_hypothesis.techniques = ["T1113"]
    hecate.hypothesis_generator.return_value = sample_hypothesis
    # One technique the item's own wording supports, so a draft is written
    # either way and only T1113's fate depends on the research grounding.
    hecate.candidate_techniques.return_value = [("T1059.003", "Windows Command Shell")]
    hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1113",
        name="Screen Capture",
        tactics=["collection"],
        platforms=["Windows"],
        found=True,
    )
    frontmatter = _run(settings, hecate).draft_path.read_text().split("---", 2)[1]
    return next(line for line in frontmatter.splitlines() if line.startswith("techniques:"))


def test_source_only_research_cannot_support_a_technique(
    settings: Settings, source_only: MagicMock, sample_hypothesis: HypothesisResult
) -> None:
    """The CTI never mentions screen capture; source-only research rephrasing it adds no evidence."""
    assert "T1113" not in _research_only_technique(settings, source_only, sample_hypothesis)


def test_independent_research_can_support_a_technique(
    settings: Settings, independent: MagicMock, sample_hypothesis: HypothesisResult
) -> None:
    assert "T1113" in _research_only_technique(settings, independent, sample_hypothesis)


def test_research_result_grounding_labels() -> None:
    assert ResearchResult(web_searches=2).grounding == "independent"
    assert (
        ResearchResult(web_searches=0).grounding_label() == "source-only synthesis, 0 web searches"
    )
    assert (
        ResearchResult(web_searches=0, web_search_note="x").grounding_label()
        == "source-only synthesis, 0 web searches: x"
    )
