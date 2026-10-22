"""Phrase-matched ATT&CK candidates are merged into a draft's techniques."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.hecate_client import (
    HecateClient,
    HypothesisResult,
    ResearchResult,
    TechniqueMetadata,
)
from hecate_runner.orchestrator import Orchestrator, research_tradecraft_text

_RESEARCH_DOC = """# R-0009: BengalSEO Research

## 1. System Research: How It Works

### Summary
Search engines rank pages.

## 2. Adversary Tradecraft: Attack Techniques

### Summary
The operators use SEO poisoning to push malicious pages up Bing results.

## 3. Telemetry Mapping: OCSF Fields

### Summary
Gaps: consider process injection telemetry.
"""


def _queue(workspace: Path, text: str) -> FileQueueProvider:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(text)
    return provider


def test_tradecraft_section_is_all_that_is_matched() -> None:
    section = research_tradecraft_text(_RESEARCH_DOC)
    assert "SEO poisoning" in section
    assert "process injection" not in section  # speculation from section 3
    assert "Search engines rank" not in section
    assert research_tradecraft_text("") == ""


def test_candidates_come_from_primary_cti_and_join_model_picks(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
    sample_hypothesis: HypothesisResult,
) -> None:
    """Research may inform context, but only primary CTI supplies candidates."""
    (workspace / "research").mkdir(exist_ok=True)
    (workspace / "research" / "R-0009.md").write_text(_RESEARCH_DOC)
    mock_hecate.research_new.return_value = ResearchResult(research_id="R-0009")
    sample_hypothesis.techniques = ["T1098"]
    mock_hecate.candidate_techniques.return_value = [("T1608.006", "SEO Poisoning")]

    def lookup_technique(technique_id: str, **_kwargs: object) -> TechniqueMetadata:
        return TechniqueMetadata(
            technique_id=technique_id,
            name="SEO Poisoning" if technique_id == "T1608.006" else "Account Manipulation",
            tactics=["initial-access"],
            platforms=["Windows"],
            found=True,
        )

    mock_hecate.lookup_technique.side_effect = lookup_technique
    provider = _queue(
        workspace,
        "RSS: BengalSEO\nSource: thedfirreport.com\n"
        "Summary: An SEO poisoning campaign leading to malware deployment.\n"
        "Link: https://thedfirreport.com/x",
    )

    result = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    matched_text = mock_hecate.candidate_techniques.call_args.args[0]
    assert "SEO poisoning campaign" in matched_text  # the CTI
    assert "push malicious pages up Bing" not in matched_text  # secondary research
    assert "process injection" not in matched_text  # research speculation
    assert result.draft_path is not None
    frontmatter = result.draft_path.read_text().split("---")[1]
    assert 'techniques: ["T1608.006"]' in frontmatter


def test_an_indicator_dump_gets_no_candidates(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    provider = _queue(
        workspace,
        "MISP Event: ThreatFox IOCs for 2026-08-05\nOrg: ThreatFox\n"
        "Attributes (42 total): domain (10), ip-dst (20), url (12)",
    )
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()
    mock_hecate.candidate_techniques.assert_not_called()


class TestClientCandidates:
    @pytest.fixture
    def client(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HecateClient:
        c = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)
        monkeypatch.setattr(c, "_with_context", lambda func, *a, **kw: func(*a, **kw))
        return c

    @staticmethod
    def _install(monkeypatch: pytest.MonkeyPatch, func: object) -> None:
        # A stand-in module, so these tests do not depend on which Hecate
        # version the test environment has installed.
        module = types.ModuleType("hecate_agent.core.technique_candidates")
        module.candidate_techniques = func  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "hecate_agent.core.technique_candidates", module)

    def test_returns_what_hecate_matched(
        self, client: HecateClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._install(monkeypatch, lambda text: [("T1036", "Masquerading")])
        assert client.candidate_techniques("masquerades") == [("T1036", "Masquerading")]

    def test_a_failure_costs_the_candidates_not_the_cycle(
        self, client: HecateClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(text: str) -> list[tuple[str, str]]:
            raise RuntimeError("stix unavailable")

        self._install(monkeypatch, boom)
        assert client.candidate_techniques("anything") == []

    def test_an_older_hecate_without_the_module_yields_nothing(
        self, client: HecateClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "hecate_agent.core.technique_candidates", None)
        assert client.candidate_techniques("anything") == []
