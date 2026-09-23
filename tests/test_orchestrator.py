"""Orchestrator loop tests. Uses mocks for HecateClient so no real hecate runs."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import (
    HecateClient,
    HecateError,
    HypothesisResult,
    ResearchResult,
    SigmaResult,
    TechniqueMetadata,
)
from hecate_runner.indicator_sweep import parse_indicator_inventory
from hecate_runner.orchestrator import (
    _MAX_SKIPS_PER_CYCLE,
    Orchestrator,
    derive_data_sources,
    derive_research_topic,
    has_narrative,
    merge_techniques,
    platform_consistent_data_sources,
    platforms_named_in,
    substantive_observables,
)
from hecate_runner.parked_store import list_parked
from hecate_runner.state import OrchestratorState

_SIGMA_RULE = {
    "logsource_category": "network_connection",
    "title": "Chrysalis C2 beacon",
    "level": "high",
    "techniques": ["T1071.001"],
    "rule_yaml": "title: Chrysalis C2 beacon\n",
}


@pytest.fixture
def mock_hecate(
    sample_hypothesis: HypothesisResult,
    sample_research_result: ResearchResult,
) -> MagicMock:
    mock = MagicMock(spec=HecateClient)
    mock.hypothesis_generator.return_value = sample_hypothesis
    mock.research_new.return_value = sample_research_result
    # Matches sample_hypothesis's T1003.001 so tests asserting on rendered
    # draft content see real-looking tactics/platform, not an empty lookup.
    mock.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1003.001",
        tactics=["credential-access"],
        platforms=["Windows"],
        found=True,
    )
    # Default to the failure path so tests that are not about Sigma exercise
    # the graceful degradation. Left as a bare MagicMock this silently
    # rendered a "0 Sigma rule(s)" header into every draft under test, via
    # MagicMock's default __len__/__iter__ -- passing, but testing nothing.
    mock.sigma_generator.return_value = SigmaResult(
        success=False, error="sigma generation not configured in this test"
    )
    return mock


def test_no_cti_returns_no_cti(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()
    assert result.outcome == "no_cti"
    mock_hecate.hypothesis_generator.assert_not_called()


def test_happy_path_creates_draft(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
) -> None:
    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()

    assert result.outcome == "draft_created"
    assert result.hunt_id == "H-0001"
    assert result.draft_path is not None
    assert result.draft_path.exists()
    assert result.research_id == "R-0001"
    content = result.draft_path.read_text()
    assert "LSASS memory" in content
    assert "requires-human-review" in content
    assert "spawned_from: R-0001" in content

    # CTI file archived
    assert not (workspace / "cti_queue" / "next.txt").exists()
    processed = list((workspace / "cti_queue" / "processed").glob("cti-*.txt"))
    assert len(processed) == 1

    mock_hecate.research_new.assert_called_once()
    mock_hecate.hypothesis_generator.assert_called_once()
    # research_id from the grounding step must flow into hypothesis generation
    assert mock_hecate.hypothesis_generator.call_args.kwargs["research_id"] == "R-0001"


def test_parseable_indicator_dump_skips_research_and_llm(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    # Regression test for the ThreatFox-style bare IOC dump that fabricated
    # "PureRAT and Overlord RAT" after web search grounded against wrong-
    # dated pages of the same recurring aggregator title (see has_narrative).
    #
    # Research used to run here with web search disabled, which produced four
    # skills' worth of "insufficient information" boilerplate (~2 min, 4 LLM
    # calls) that the draft then linked as "detailed pre-hunt research". A
    # sweep draft is built from the indicator inventory alone, so neither call
    # is made now -- a strictly stronger guarantee than disabling web search.
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "MISP Event: ThreatFox IOCs for 2026-08-05\n"
        "Org: ThreatFox\n"
        "Threat Level: Medium\n"
        "TLP: white\n"
        "Attributes (42 total): domain (10), ip-dst (20), url (12)"
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "draft_created"
    mock_hecate.research_new.assert_not_called()
    # A readable indicator inventory means the draft is built directly, with
    # no LLM call at all -- there is no slot left for the model to invent a
    # delivery vector or technique into.
    mock_hecate.hypothesis_generator.assert_not_called()
    assert result.research_id is None


def test_free_form_cti_without_any_marker_still_reaches_the_llm(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """`has_narrative` recognises the markers provider blurbs use, so its
    absence is not evidence that no narrative exists. The file queue takes
    hand-written text carrying no marker at all; skipping on that basis would
    discard real CTI, which is worse than the empty draft C4 set out to stop."""
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "APT actor X observed dumping LSASS via comsvcs.dll on Windows endpoints."
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "draft_created"
    assert mock_hecate.hypothesis_generator.call_args.kwargs["indicators_only"] is True
    assert mock_hecate.research_new.call_args.kwargs["web_search_enabled"] is False


def test_a_blurb_that_is_only_metadata_is_skipped(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """C4: no narrative field, no indicator inventory and no prose means
    nothing to hunt. H-0630 -- title, source, tags, link off a vendor
    marketing post -- became "Indicators published in <title> appear in
    telemetry", a sweep for indicators that do not exist."""
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "RSS: Teaching AI to Reason Through Detection Triage\n"
        "Source: crowdstrike.com\n"
        "Tags: Agentic SOC\n"
        "Link: https://www.crowdstrike.com/en-us/blog/teaching-ai-to-reason/"
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "no_actionable_cti"
    assert result.ok is True
    mock_hecate.hypothesis_generator.assert_not_called()
    mock_hecate.research_new.assert_not_called()


def test_skipping_costs_no_draft_quota(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """Walking past an item is not a draft. The check runs ahead of the
    reservation so a feed of marketing posts cannot exhaust the daily quota."""
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "RSS: X\nSource: y.example\nLink: https://y.example/p"
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    orch.run_once()

    assert OrchestratorState.load(settings.state_file).drafts_today == 0


def test_a_skipped_item_is_acknowledged_so_the_cursor_advances(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """Without the cursor advance the same item is re-offered every cycle."""
    provider = MagicMock()
    provider.next_item.side_effect = [
        CTIItem(
            content="RSS: X\nSource: y.example\nLink: https://y.example/p",
            source="rss",
            metadata={},
        ),
        None,
    ]
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    orch.run_once()

    provider.acknowledge.assert_called_once()


def test_the_skip_scan_is_bounded(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """A feed of nothing but marketing posts should cost one cycle, not an
    unbounded walk through the archive."""
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="RSS: X\nSource: y.example\nLink: https://y.example/p", source="rss", metadata={}
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "no_actionable_cti"
    assert provider.next_item.call_count <= _MAX_SKIPS_PER_CYCLE + 1


def test_a_provider_that_cannot_advance_is_not_spun_on(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """If acknowledge fails the same item comes back, so stopping is the only
    way not to loop on it."""
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="RSS: X\nSource: y.example\nLink: https://y.example/p", source="rss", metadata={}
    )
    provider.acknowledge.side_effect = RuntimeError("cursor write failed")
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "no_actionable_cti"
    assert provider.next_item.call_count == 1


def test_indicator_dump_draft_has_no_techniques_and_no_invented_behavior(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "MISP Event: ThreatFox IOCs for 2026-08-09\n"
        "Org: abuse.ch\n"
        "Attributes (245 total): domain (146), ip-dst|port (78), url (21)"
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.draft_path is not None
    content = result.draft_path.read_text()
    assert "techniques: []" in content
    assert "TXXXX" not in content
    assert "Indicators published in ThreatFox IOCs for 2026-08-09" in content
    for fabrication in ("phishing", "lateral movement", "stolen credentials"):
        assert fabrication not in content.lower()


def test_narrative_cti_keeps_web_search_enabled(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    (file_queue_with_cti.queue_dir / "next.txt").write_text(
        "RSS: Some Campaign\n"
        "Source: example.com\n"
        "Summary: Attackers observed doing something specific and narrative-worthy.\n"
        "Link: https://example.com/post"
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    orch.run_once()

    assert mock_hecate.research_new.call_args.kwargs["web_search_enabled"] is True
    assert mock_hecate.hypothesis_generator.call_args.kwargs["indicators_only"] is False


def test_related_hunts_from_research_flow_into_draft(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    sample_research_result: ResearchResult,
) -> None:
    # A research step that found related past hunts (see
    # HuntResearcherAgent._skill_4_related_work in hecate) must actually land
    # in the draft's related_hunts frontmatter, not the hardcoded [] this
    # regression-tests against.
    mock_hecate.research_new.return_value = ResearchResult(
        research_id=sample_research_result.research_id,
        recommended_hypothesis=sample_research_result.recommended_hypothesis,
        related_hunts=["H-0602", "H-0578"],
    )
    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()

    assert result.outcome == "draft_created"
    content = result.draft_path.read_text()
    assert 'related_hunts: ["H-0602", "H-0578"]' in content


def test_dry_run_does_not_call_hecate(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
) -> None:
    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once(dry_run=True)
    assert result.outcome == "dry_run"
    mock_hecate.research_new.assert_not_called()
    mock_hecate.hypothesis_generator.assert_not_called()
    # CTI stays in the queue
    assert (workspace / "cti_queue" / "next.txt").exists()


def test_quota_enforcement(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "1")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=file_queue_with_cti,
    )
    first = orch.run_once()
    assert first.outcome == "draft_created"

    # Put a second CTI in and try again
    (workspace / "cti_queue" / "next.txt").write_text("another intel")
    second = orch.run_once()
    assert second.outcome == "quota_reached"
    # Ensure hypothesis-generator only called once
    assert mock_hecate.hypothesis_generator.call_count == 1


def test_hecate_error_refunds_quota(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    sample_research_result: ResearchResult,
) -> None:
    failing_hecate = MagicMock(spec=HecateClient)
    failing_hecate.research_new.return_value = sample_research_result
    failing_hecate.hypothesis_generator.side_effect = HecateError("simulated failure")

    orch = Orchestrator(
        settings=settings,
        hecate=failing_hecate,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()
    assert result.outcome == "hecate_error"
    # CTI stays in queue for retry
    assert (workspace / "cti_queue" / "next.txt").exists()


def test_write_failure_refunds_quota_and_leaves_cti_queued(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    mock_hecate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression test: next_hunt_id()/write_draft() had no failure handling
    at all -- a disk/permission error there used to propagate to the
    top-level catch-all, permanently burning a quota slot with nothing
    produced and no refund."""
    import hecate_runner.orchestrator as orchestrator_module

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(orchestrator_module, "write_draft", _boom)

    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    assert result.outcome == "write_error"
    # CTI stays in queue for retry -- it was never acknowledged.
    assert (workspace / "cti_queue" / "next.txt").exists()


def test_acknowledge_failure_does_not_fail_the_cycle_or_refund_quota(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    """Regression test: self.cti.acknowledge(item) ran unguarded AFTER the
    draft file was already written. If it raised, the exception propagated
    to run_once()'s top-level catch-all, which (a) marked the whole cycle as
    failed (state.mark_run(success=False)) despite a real draft having been
    produced, and (b) left the CTI item's cursor unadvanced, so it would be
    picked up and re-drafted under a new ID next cycle -- duplicate content,
    a second quota slot burned. A real draft on disk must count as success,
    not a cycle failure, even when acknowledge() itself blows up."""

    class _AcknowledgeFailsProvider:
        def __init__(self, inner: FileQueueProvider) -> None:
            self._inner = inner

        def next_item(self):  # type: ignore[no-untyped-def]
            return self._inner.next_item()

        def acknowledge(self, item: object) -> None:
            raise RuntimeError("simulated acknowledge failure")

    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=_AcknowledgeFailsProvider(file_queue_with_cti),  # type: ignore[arg-type]
    )
    result = orch.run_once()

    # The draft still succeeded -- acknowledge() failing is isolated, not a
    # cycle-level failure, and quota is NOT refunded (a real draft exists).
    assert result.outcome == "draft_created"
    assert result.draft_path is not None
    assert result.draft_path.exists()


def test_empty_hypothesis_refunds_quota(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    sample_research_result: ResearchResult,
) -> None:
    empty_hecate = MagicMock(spec=HecateClient)
    empty_hecate.research_new.return_value = sample_research_result
    empty_hecate.hypothesis_generator.return_value = HypothesisResult()

    orch = Orchestrator(
        settings=settings,
        hecate=empty_hecate,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()
    assert result.outcome == "empty_hypothesis"


def test_research_disabled_skips_research_call(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HECATE_RUNNER_RESEARCH_ENABLED", "false")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    assert result.outcome == "draft_created"
    assert result.research_id is None
    mock_hecate.research_new.assert_not_called()
    assert mock_hecate.hypothesis_generator.call_args.kwargs["research_id"] is None


def test_research_failure_aborts_cycle(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
) -> None:
    mock_hecate.research_new.side_effect = HecateError("ollama timed out")

    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    # Cold generation is unreliable (~30% accuracy on known-answer fixtures),
    # so a grounding failure must refuse to fall back to an ungrounded draft.
    assert result.outcome == "research_error"
    assert result.research_id is None
    assert result.draft_path is None
    assert not result.ok
    mock_hecate.hypothesis_generator.assert_not_called()

    # Quota refunded and CTI left in queue for retry, same as any other failure.
    assert (workspace / "cti_queue" / "next.txt").exists()

    from hecate_runner.state import OrchestratorState

    state = OrchestratorState.load(settings.state_file)
    assert state.drafts_today == 0


def test_research_quota_survives_failed_cycle_refunds(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A failed cycle refunds its draft slot, but the searches it made are spent.
    # The retry next hour must hit the research cap, not search again.
    monkeypatch.setenv("HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY", "1")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    (file_queue_with_cti.queue_dir / "next.txt").write_text(
        "RSS: Some Campaign\n"
        "Source: example.com\n"
        "Summary: Attackers observed doing something specific and narrative-worthy.\n"
        "Link: https://example.com/post"
    )
    mock_hecate.research_new.side_effect = HecateError("ollama timed out")
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    first = orch.run_once()
    assert first.outcome == "research_error"
    assert mock_hecate.research_new.call_args.kwargs["web_search_enabled"] is True

    second = orch.run_once()
    assert second.outcome == "research_quota_reached"
    assert second.ok
    assert mock_hecate.research_new.call_count == 1
    mock_hecate.hypothesis_generator.assert_not_called()
    assert (workspace / "cti_queue" / "next.txt").exists()

    state = OrchestratorState.load(settings.state_file)
    assert state.drafts_today == 0
    assert state.research_runs_today == 1


def test_research_quota_ignores_runs_without_web_search(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Research with search disabled spends no Tavily credits, so a zero cap
    # must not block it.
    monkeypatch.setenv("HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY", "0")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    monkeypatch.setattr("hecate_runner.orchestrator.has_narrative", lambda _content: False)
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    result = orch.run_once()

    assert result.outcome != "research_quota_reached"
    assert mock_hecate.research_new.call_args.kwargs["web_search_enabled"] is False
    assert OrchestratorState.load(settings.state_file).research_runs_today == 0


def test_research_failure_does_not_notify(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    mock_hecate.research_new.side_effect = HecateError("ollama timed out")
    notify = MagicMock()

    orch = Orchestrator(
        settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti, notify=notify
    )
    orch.run_once()

    notify.assert_not_called()


def test_research_empty_result_aborts_cycle(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    mock_hecate.research_new.return_value = ResearchResult()  # empty research_id

    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    assert result.outcome == "research_empty"
    assert result.research_id is None
    assert not result.ok
    mock_hecate.hypothesis_generator.assert_not_called()


@pytest.mark.parametrize(
    ("content", "expected_technique"),
    [
        ("APT actor X observed using T1053.005 scheduled tasks", "T1053.005"),
        ("Adversaries dumping LSASS via T1003.001 comsvcs.dll", "T1003.001"),
        ("No technique mentioned here at all", None),
    ],
)
def test_derive_research_topic_extracts_technique(
    content: str, expected_technique: str | None
) -> None:
    _, technique = derive_research_topic(content)
    assert technique == expected_technique


def test_derive_research_topic_truncates_long_content() -> None:
    long_content = "word " * 60  # 300 chars, well past the 100-char cap
    topic, _ = derive_research_topic(long_content)
    assert len(topic) <= 100
    assert not topic.endswith(" ")


def test_derive_research_topic_prefers_clean_title_over_flattened_content() -> None:
    # Regression test: flattening+truncating the whole multi-field RSS blurb
    # (title + "Source: <feed>" + "Tags: ..." + "Summary: ...") at a fixed
    # char count routinely cut mid-label ("...Deliver Akira Source:") and,
    # worse, could hand the web-search agent a topic still carrying words
    # like "Bing Search" from the headline as if they were the subject.
    content = (
        "RSS: From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira\n"
        "Source: thedfirreport.com\n"
        "Tags: akira, ransomware\n"
        "Summary: Key Takeaways this case was first reported to customers...\n"
        "Link: https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware"
    )
    topic, _ = derive_research_topic(content, title="Bumblebee and AdaptixC2 Deliver Akira")
    assert topic == "Bumblebee and AdaptixC2 Deliver Akira"
    assert "Source:" not in topic
    assert "Bing Search" not in topic


def test_derive_research_topic_falls_back_to_content_without_a_title() -> None:
    topic, _ = derive_research_topic("RSS: some headline\nSource: example.com", title=None)
    assert topic.startswith("RSS: some headline")


def test_derive_research_topic_truncates_long_title_on_word_boundary() -> None:
    long_title = "word " * 60  # 300 chars, well past the 100-char cap
    topic, _ = derive_research_topic("irrelevant content body", title=long_title)
    assert len(topic) <= 100
    assert not topic.endswith(" ")


def test_has_narrative_true_for_rss_summary_line() -> None:
    content = (
        "RSS: Token Jacking: Cybercriminals Could Be Stealing Your AI Resources\n"
        "Source: unit42.paloaltonetworks.com\n"
        "Tags: Malware, Threat Research\n"
        "Summary: Discover how attackers hijack AI tokens to fuel gray market transfer stations.\n"
        "Link: https://unit42.paloaltonetworks.com/ai-token-jacking/"
    )
    assert has_narrative(content) is True


def test_has_narrative_true_for_otx_description_line() -> None:
    content = (
        "OTX Pulse: Fake Software Installers Disable Windows Update\n"
        "Adversary/Attribution: Void Arachne\n"
        "Description: An active malware campaign utilizes fraudulent software-download websites...\n"
        "Indicators (16 total): domain (16)"
    )
    assert has_narrative(content) is True


def test_has_narrative_false_for_bare_ioc_dump() -> None:
    # A MISP blurb has no prose field, so a ThreatFox-style dump reduces to
    # Org/Threat Level/TLP/Tags/attribute counts. Crucially it also carries
    # no galaxy cluster, so it reaches no ATT&CK line either -- nothing here
    # is evidence of analysed behavior.
    content = (
        "MISP Event: ThreatFox IOCs for 2026-08-05\n"
        "Org: ThreatFox\n"
        "Threat Level: Medium\n"
        "TLP: white\n"
        "Tags: type:OSINT, tlp:white\n"
        "Attributes (42 total): domain (10), ip-dst (20), url (12)"
    )
    assert has_narrative(content) is False


def test_resolve_ttps_excludes_near_universal_platforms_from_union(
    settings: Settings,
    mock_hecate: MagicMock,
    file_queue_with_cti: FileQueueProvider,
) -> None:
    # T1078 "Valid Accounts"-shaped technique: touches all ~10 ATT&CK
    # platforms and, unioned in unconditionally, swamps a genuinely narrow
    # technique (T1021.002, Windows-only) also on the same hypothesis --
    # the exact shape that made 37% of one drafting batch list every
    # ATT&CK platform verbatim regardless of what the CTI described.
    broad = TechniqueMetadata(
        technique_id="T1078",
        tactics=["persistence", "privilege-escalation", "initial-access"],
        platforms=[
            "Containers",
            "ESXi",
            "IaaS",
            "Identity Provider",
            "Linux",
            "macOS",
            "Network Devices",
            "Office Suite",
            "SaaS",
            "Windows",
        ],
        found=True,
    )
    narrow = TechniqueMetadata(
        technique_id="T1021.002",
        tactics=["lateral-movement"],
        platforms=["Windows"],
        found=True,
    )
    mock_hecate.lookup_technique.side_effect = lambda technique_id, timeout_sec: (
        broad if technique_id == "T1078" else narrow
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    tactics, platforms = orch._resolve_ttps(["T1021.002", "T1078"])

    assert platforms == ["Windows"]
    assert set(tactics) == {
        "lateral-movement",
        "persistence",
        "privilege-escalation",
        "initial-access",
    }


def test_resolve_ttps_translates_pre_platform_to_a_readable_label(
    settings: Settings,
    mock_hecate: MagicMock,
    file_queue_with_cti: FileQueueProvider,
) -> None:
    """Regression test: found via a live end-to-end run against T1598
    "Phishing for Information" -- ATT&CK's own STIX data lists its platform
    as the literal string "PRE" (pre-compromise: there's no OS/environment
    yet), and it was surfacing in hunt files verbatim as `platform: ["PRE"]`
    with nothing explaining what that meant to a human reviewer."""
    pre_compromise = TechniqueMetadata(
        technique_id="T1598",
        tactics=["reconnaissance"],
        platforms=["PRE"],
        found=True,
    )
    mock_hecate.lookup_technique.return_value = pre_compromise
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    _, platforms = orch._resolve_ttps(["T1598"])

    assert platforms == ["Pre-Compromise (reconnaissance/targeting -- not endpoint/OS-specific)"]


def test_resolve_ttps_falls_back_to_empty_platforms_when_all_techniques_are_broad(
    settings: Settings,
    mock_hecate: MagicMock,
    file_queue_with_cti: FileQueueProvider,
) -> None:
    # hunt_writer's `platforms or ["Unknown"]` fallback turns an empty list
    # into an honest gap signal -- preferable to fabricating a full-platform
    # list when nothing scoping was actually resolved.
    broad = TechniqueMetadata(
        technique_id="T1078",
        tactics=["persistence"],
        platforms=[
            "Windows",
            "Linux",
            "macOS",
            "Containers",
            "ESXi",
            "IaaS",
            "SaaS",
            "Office Suite",
        ],
        found=True,
    )
    mock_hecate.lookup_technique.return_value = broad
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    _, platforms = orch._resolve_ttps(["T1078"])

    assert platforms == []


def test_notify_called_on_draft_created(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    notify = MagicMock()
    orch = Orchestrator(
        settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti, notify=notify
    )
    result = orch.run_once()

    notify.assert_called_once()
    (notified_result,) = notify.call_args.args
    assert notified_result.outcome == "draft_created"
    assert notified_result.hunt_id == result.hunt_id


def test_notify_not_called_when_no_cti(
    settings: Settings,
    workspace: Path,
    mock_hecate: MagicMock,
) -> None:
    notify = MagicMock()
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider, notify=notify)
    orch.run_once()

    notify.assert_not_called()


def test_notify_not_called_on_dry_run(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    notify = MagicMock()
    orch = Orchestrator(
        settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti, notify=notify
    )
    orch.run_once(dry_run=True)

    notify.assert_not_called()


def test_notify_failure_does_not_corrupt_successful_outcome(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    def failing_notify(result: object) -> None:
        raise RuntimeError("slack is down")

    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=file_queue_with_cti,
        notify=failing_notify,
    )
    result = orch.run_once()

    # A raising notifier must not turn a successful draft into an error outcome.
    assert result.outcome == "draft_created"
    assert result.hunt_id is not None


def test_orchestrator_without_notify_arg_defaults_to_noop(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    result = orch.run_once()
    assert result.outcome == "draft_created"


def test_state_persists_across_runs(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
) -> None:
    orch = Orchestrator(
        settings=settings,
        hecate=mock_hecate,
        cti_provider=file_queue_with_cti,
    )
    orch.run_once()

    from hecate_runner.state import OrchestratorState

    state = OrchestratorState.load(settings.state_file)
    assert state.drafts_today == 1
    assert state.total_drafts_ever == 1
    assert state.last_run_iso != ""
    assert state.consecutive_failures == 0


# --- Empty [source] slot in an indicator-sweep hypothesis -------------------
#
# The sweep template is "Indicators published in [source] appear in
# [telemetry] on [target]". Three drafts (H-0009/0011/0013) came back with
# [source] empty, producing "Indicators published in  appear in telemetry on
# unpatched systems" -- which lands twice in the file, as the frontmatter
# title and as the Hypothesis Statement, and reads as a truncation bug rather
# than a missing value. The CTI item's own title is what belongs there.


def test_empty_source_slot_is_filled_from_the_cti_title() -> None:
    from hecate_runner.orchestrator import _fill_empty_source_slot

    result = _fill_empty_source_slot(
        "Indicators published in  appear in telemetry on unpatched systems",
        "August 2026 Patch Tuesday",
    )

    assert result == (
        "Indicators published in August 2026 Patch Tuesday appear in telemetry on unpatched systems"
    )


def test_empty_source_slot_falls_back_when_there_is_no_title() -> None:
    from hecate_runner.orchestrator import _fill_empty_source_slot

    result = _fill_empty_source_slot("Indicators published in  appear in telemetry", None)

    assert result == "Indicators published in the source feed appear in telemetry"
    assert "  " not in result


def test_a_well_formed_sweep_hypothesis_is_untouched() -> None:
    from hecate_runner.orchestrator import _fill_empty_source_slot

    original = "Indicators published in ThreatFox IOCs for 2026-08-11 appear in telemetry"

    assert _fill_empty_source_slot(original, "ThreatFox IOCs") == original


def test_a_behavioral_hypothesis_is_untouched() -> None:
    from hecate_runner.orchestrator import _fill_empty_source_slot

    original = "Adversaries use Radmin and UltraVNC to establish persistent control"

    assert _fill_empty_source_slot(original, "Some CTI title") == original


def test_a_title_containing_regex_metacharacters_is_inserted_literally() -> None:
    """The replacement runs through re.sub, so a title carrying a backslash or
    a group reference must not be interpreted as a template."""
    from hecate_runner.orchestrator import _fill_empty_source_slot

    result = _fill_empty_source_slot(
        "Indicators published in  appear in telemetry", r"Feed \1 (a\b) [x]"
    )

    assert r"Feed \1 (a\b) [x]" in result


def test_has_narrative_true_for_curated_misp_event_with_attack_line() -> None:
    """A curated MISP event has no prose field but does state techniques.

    This is the real shape of the events the galaxy filter and org allowlist
    exist to select. Classifying it as a bare dump routed it past research
    and rendered it with `techniques: []` -- discarding the very mapping it
    was selected for.
    """
    content = (
        "MISP Event: The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit\n"
        "Org: CUDESO\n"
        "Threat Level: Medium\n"
        "TLP: clear\n"
        "MITRE ATT&CK Techniques: T1005, T1027.007, T1041, T1059.003, T1071.001\n"
        "Attributes (20 total): comment (1), filename (2), hostname (2), ip-dst (4)"
    )
    assert has_narrative(content) is True


def test_curated_misp_event_is_not_classified_as_an_indicator_sweep() -> None:
    """The consequence that actually mattered, asserted end to end."""
    content = (
        "MISP Event: The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit\n"
        "Org: CUDESO\n"
        "MITRE ATT&CK Techniques: T1005, T1027.007, T1041\n"
        "Attributes (20 total): hostname (2), ip-dst (4), url (9)"
    )
    assert has_narrative(content) is True
    # sweep_inventory is only computed when the narrative check fails, so a
    # True here is exactly what keeps this off the template path.
    assert parse_indicator_inventory(content)  # it *would* have parsed as one


def test_attack_line_constant_matches_what_every_provider_emits() -> None:
    """Guards the drift the shared constant exists to prevent.

    has_narrative reads this label back out of rendered text. If any producer
    stopped emitting the exact string, curated events would silently start
    classifying as dumps again -- the original bug.
    """
    from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE

    for module in ("misp", "otx", "rss"):
        src = Path(f"src/hecate_runner/cti/{module}.py").read_text()
        assert "MITRE ATT&CK Techniques:" not in src, (
            f"{module}.py hardcodes the label instead of using ATTACK_TECHNIQUE_LINE"
        )
    rendered = f"{ATTACK_TECHNIQUE_LINE} T1059.003"
    assert has_narrative(rendered) is True


# --- Sigma drafting --------------------------------------------------------


def test_sigma_rules_are_embedded_in_the_draft(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    workspace: Path,
) -> None:
    mock_hecate.sigma_generator.return_value = SigmaResult(success=True, rules=[_SIGMA_RULE])
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    result = orch.run_once()
    assert result.outcome == "draft_created"
    content = result.draft_path.read_text()
    assert "Chrysalis C2 beacon" in content
    assert "1 Sigma rule(s) auto-drafted" in content
    # The review gate must survive generation.
    assert "Unreviewed" in content


def test_sigma_failure_leaves_the_draft_standing(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    """A drafting failure must not cost the hunt -- the CTI has already been
    consumed and the quota already spent by this point."""
    mock_hecate.sigma_generator.side_effect = HecateError("ollama unreachable")
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    result = orch.run_once()
    assert result.outcome == "draft_created"
    assert "[Human to draft based on Observe section" in result.draft_path.read_text()


def test_sigma_generation_can_be_disabled(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    settings.sigma_generation_enabled = False
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    assert orch.run_once().outcome == "draft_created"
    mock_hecate.sigma_generator.assert_not_called()


def test_sigma_uses_cti_techniques_over_the_narrower_hypothesis_list(
    settings: Settings,
    mock_hecate: MagicMock,
    workspace: Path,
) -> None:
    """The hypothesis narrows to what it reasoned about; the source event
    asserted fifteen techniques, and the applicable log sources follow from
    all of them."""
    from hecate_runner.cti.base import CTIItem

    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="MISP Event: X\nMITRE ATT&CK Techniques: T1071.001\nSummary: prose",
        source="misp",
        metadata={
            "techniques": ["T1071.001", "T1547.001", "T1005"],
            "indicators": {"hostname": ["api.wiresguard.com"]},
        },
    )
    mock_hecate.sigma_generator.return_value = SigmaResult(success=True, rules=[_SIGMA_RULE])
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    assert orch.run_once().outcome == "draft_created"
    payload = mock_hecate.sigma_generator.call_args.args[0]
    assert payload["techniques"] == ["T1071.001", "T1547.001", "T1005"]
    assert payload["indicators"] == {"hostname": ["api.wiresguard.com"]}


# --- Technique / platform / data-source fidelity ---------------------------

_CHRYSALIS_CTI_TECHNIQUES = [
    "T1005",
    "T1027.007",
    "T1041",
    "T1059.003",
    "T1070.004",
    "T1071.001",
    "T1543.003",
    "T1547.001",
    "T1574.002",
]


def test_merge_techniques_keeps_subtechnique_precision() -> None:
    """T1059.003 is Windows-only; bare T1059 spans five platforms, so the
    generalisation propagated straight into the platform list."""
    merged = merge_techniques(["T1059.003"], ["T1059"])
    assert merged == ["T1059.003"]


def test_merge_techniques_keeps_everything_the_cti_asserted() -> None:
    merged = merge_techniques(_CHRYSALIS_CTI_TECHNIQUES, ["T1059", "T1005"])
    assert len(merged) == len(_CHRYSALIS_CTI_TECHNIQUES)
    assert merged[0] == "T1005"  # CTI order leads


def test_merge_techniques_keeps_hypothesis_only_techniques() -> None:
    assert "T1566" in merge_techniques(["T1005"], ["T1566"])


def test_merge_techniques_keeps_a_parent_with_no_child_present() -> None:
    assert merge_techniques(["T1059"], []) == ["T1059"]


def test_platforms_named_in_reads_the_hypothesis() -> None:
    assert platforms_named_in("... on compromised Windows systems") == ["Windows"]
    assert platforms_named_in("no platform named here") == []


def test_derive_data_sources_covers_network_when_the_cti_carried_c2() -> None:
    """The hunt was scoped to process_execution alone despite two C2
    hostnames, four IPs and nine URLs in the source event."""
    sources = derive_data_sources(_CHRYSALIS_CTI_TECHNIQUES, ["hostname", "ip-dst", "url"])
    assert "network_connections" in sources
    assert "registry_events" in sources
    assert "file_operations" in sources


def test_derive_data_sources_handles_both_provider_spellings() -> None:
    assert derive_data_sources([], ["IPv4"]) == ["network_connections"]
    assert derive_data_sources([], ["FileHash-SHA256"]) == ["file_operations"]


def test_resolve_ttps_scopes_platforms_to_what_the_hypothesis_claims(
    settings: Settings, mock_hecate: MagicMock
) -> None:
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1059",
        tactics=["execution"],
        platforms=["ESXi", "Linux", "macOS", "Network Devices", "Windows"],
        found=True,
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())

    _, platforms = orch._resolve_ttps(["T1059"], scope_text="on compromised Windows systems")
    assert platforms == ["Windows"]


def test_resolve_ttps_keeps_the_union_when_nothing_is_claimed(
    settings: Settings, mock_hecate: MagicMock
) -> None:
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1059", tactics=["execution"], platforms=["Linux", "Windows"], found=True
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())
    _, platforms = orch._resolve_ttps(["T1059"], scope_text="")
    assert platforms == ["Linux", "Windows"]


def test_resolve_ttps_ignores_a_claim_no_technique_supports(
    settings: Settings, mock_hecate: MagicMock
) -> None:
    """Narrowing only. A hypothesis naming Linux must not add Linux to a
    Windows-only technique."""
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1059.003", tactics=["execution"], platforms=["Windows"], found=True
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())
    _, platforms = orch._resolve_ttps(["T1059.003"], scope_text="Linux servers")
    assert platforms == ["Windows"]


def test_draft_records_cti_techniques_and_scoped_platform(
    settings: Settings, mock_hecate: MagicMock, sample_hypothesis: HypothesisResult
) -> None:
    sample_hypothesis.hypothesis = (
        "Adversaries run obfuscated commands on compromised Windows systems"
    )
    sample_hypothesis.techniques = ["T1059"]
    mock_hecate.hypothesis_generator.return_value = sample_hypothesis
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1059.003", tactics=["execution"], platforms=["Windows"], found=True
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="MISP Event: X\nMITRE ATT&CK Techniques: T1059.003\nSummary: prose",
        source="misp",
        metadata={
            "techniques": ["T1059.003", "T1071.001"],
            "indicators": {"hostname": ["api.wiresguard.com"]},
        },
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()
    content = result.draft_path.read_text()
    assert "T1059.003" in content
    assert '"T1059"' not in content  # the generalisation must not survive
    assert 'platform: ["Windows"]' in content
    assert "network_connections" in content  # derived from the C2 hostname


def test_draft_never_invents_a_vendor_data_source(
    settings: Settings, mock_hecate: MagicMock, sample_hypothesis: HypothesisResult
) -> None:
    sample_hypothesis.data_sources = []
    sample_hypothesis.techniques = []
    mock_hecate.hypothesis_generator.return_value = sample_hypothesis
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="RSS: X\nSummary: prose", source="rss", metadata={}
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    content = orch.run_once().draft_path.read_text()
    assert "CrowdStrike" not in content
    assert "data_sources: []" in content


def test_research_is_linked_back_to_the_hunt(
    settings: Settings, file_queue_with_cti: FileQueueProvider, mock_hecate: MagicMock
) -> None:
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    result = orch.run_once()
    mock_hecate.link_research_to_hunt.assert_called_once()
    args = mock_hecate.link_research_to_hunt.call_args.args
    assert args[1] == result.hunt_id


def test_link_failure_does_not_lose_the_hunt(
    settings: Settings, file_queue_with_cti: FileQueueProvider, mock_hecate: MagicMock
) -> None:
    mock_hecate.link_research_to_hunt.side_effect = HecateError("hecate exit 1")
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)
    assert orch.run_once().outcome == "draft_created"


def test_invalid_technique_is_dropped_from_draft(
    settings: Settings, mock_hecate: MagicMock, sample_hypothesis: HypothesisResult
) -> None:
    """An invented technique ID must be dropped so it doesn't break frontmatter validation."""
    sample_hypothesis.techniques = ["T9999"]
    mock_hecate.hypothesis_generator.return_value = sample_hypothesis
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(technique_id="T9999", found=False)
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="RSS: X\nSummary: prose", source="rss", metadata={}
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    content = orch.run_once().draft_path.read_text()
    assert "T9999" not in content
    assert "none mapped - human to populate" in content


def test_revoked_technique_is_recorded_in_the_draft(
    settings: Settings, mock_hecate: MagicMock, sample_hypothesis: HypothesisResult
) -> None:
    sample_hypothesis.techniques = ["T1574.002"]
    mock_hecate.hypothesis_generator.return_value = sample_hypothesis
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1574.001",
        tactics=["defense-evasion"],
        platforms=["Windows"],
        found=True,
        superseded_from="T1574.002",
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="MISP Event: X\nMITRE ATT&CK Techniques: T1574.002\nSummary: prose",
        source="misp",
        metadata={"techniques": ["T1574.002"]},
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    content = orch.run_once().draft_path.read_text()
    assert "superseded by T1574.001" in content


# --- Intake triage parks commentary rather than drafting it (C4) ------------

_ROUNDUP = CTIItem(
    content="RSS: The Good, the Bad and the Ugly - Week 33\nSummary: Courts sentence a Com member; advisory warns of Gunra ransomware.",
    source="rss",
    title="The Good, the Bad and the Ugly in Cybersecurity - Week 33 (2026)",
    identifier="https://example-feed.test/w33",
    metadata={"entry_tags": ["The Good, the Bad and the Ugly"]},
)
_REAL = CTIItem(
    content="RSS: Lynx Ransomware\nSummary: Lynx ransomware deployed after RDP access; C2 over HTTPS.",
    source="rss",
    title="Cat's Got Your Files: Lynx Ransomware",
    identifier="https://example-feed.test/lynx",
    metadata={"entry_tags": ["Malware"]},
)


def test_commentary_is_parked_instead_of_drafted(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, None]
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "no_actionable_cti"
    mock_hecate.hypothesis_generator.assert_not_called()
    parked = list_parked(settings.cti_queue_dir_resolved)
    assert len(parked) == 1
    assert "the good, the bad and the ugly" in parked[0].reason


def test_a_parked_item_keeps_its_content_so_it_can_be_replayed(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    """The cursor has advanced by now, so this copy is the only one left."""
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, None]
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    assert list_parked(settings.cti_queue_dir_resolved)[0].content == _ROUNDUP.content


def test_parking_advances_the_cursor(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, None]
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    provider.acknowledge.assert_called_once()


def test_the_cycle_moves_on_to_the_next_item_after_parking(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    """Parking must not cost the cycle: the real item behind it still drafts."""
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, _REAL]
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "draft_created"
    assert len(list_parked(settings.cti_queue_dir_resolved)) == 1


def test_parking_costs_no_draft_quota(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, None]
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    assert OrchestratorState.load(settings.state_file).drafts_today == 0


def test_real_intelligence_is_not_parked(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    provider = MagicMock()
    provider.next_item.side_effect = [_REAL, None]
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    assert orch.run_once().outcome == "draft_created"
    assert list_parked(settings.cti_queue_dir_resolved) == []


def test_triage_can_be_turned_off(
    settings: Settings, workspace: Path, mock_hecate: MagicMock
) -> None:
    settings.cti_triage = "off"
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, None]
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    assert orch.run_once().outcome == "draft_created"
    assert list_parked(settings.cti_queue_dir_resolved) == []


def test_an_unwritable_park_drafts_rather_than_losing_the_item(
    settings: Settings, workspace: Path, mock_hecate: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Parking is the whole safety net. If it cannot be written, the item must
    still not disappear."""
    provider = MagicMock()
    provider.next_item.side_effect = [_ROUNDUP, None]
    monkeypatch.setattr(
        "hecate_runner.orchestrator.park",
        MagicMock(side_effect=OSError("read-only filesystem")),
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)

    assert orch.run_once().outcome == "draft_created"


class TestPlatformConsistentDataSources:
    """A macOS hunt shipped asking for `registry_events`. The hypothesis agent
    proposes its own data_sources and nothing checked them against the platform
    the techniques resolved to."""

    SOURCES: ClassVar[list[str]] = [
        "process_execution",
        "file_operations",
        "network_connections",
        "registry_events",
    ]

    def test_registry_events_dropped_on_macos(self):
        kept = platform_consistent_data_sources(self.SOURCES, ["macOS"])
        assert "registry_events" not in kept
        assert kept == ["process_execution", "file_operations", "network_connections"]

    def test_registry_events_kept_on_windows(self):
        assert "registry_events" in platform_consistent_data_sources(self.SOURCES, ["Windows"])

    def test_registry_events_kept_when_any_platform_supports_it(self):
        kept = platform_consistent_data_sources(self.SOURCES, ["macOS", "Windows"])
        assert "registry_events" in kept

    def test_unknown_platform_drops_nothing(self):
        """Empty platforms means scope is unknown, not that everything is
        excluded. Narrowing telemetry on no evidence is worse than leaving a
        source a reviewer can strike out."""
        assert platform_consistent_data_sources(self.SOURCES, []) == self.SOURCES

    def test_case_and_whitespace_insensitive(self):
        assert "registry_events" not in platform_consistent_data_sources(self.SOURCES, ["  macos "])


class TestSubstantiveObservables:
    """ "What Suspicious Looks Like" came back as the telemetry list retitled,
    which tells a reviewer nothing while reading as a completed section."""

    def test_bare_category_names_are_dropped(self):
        assert (
            substantive_observables(["Process execution", "Network connections", "File operations"])
            == []
        )

    def test_a_described_behaviour_is_kept(self):
        observables = ["Process execution", "Unsigned binary launched from /tmp by Safari"]
        assert substantive_observables(observables) == [
            "Unsigned binary launched from /tmp by Safari"
        ]

    def test_specific_entries_survive_untouched(self):
        observables = ["DNS query to a newly registered lookalike domain"]
        assert substantive_observables(observables) == observables

    def test_trailing_punctuation_and_underscores_normalise(self):
        assert substantive_observables(["registry_events.", "Network Connections"]) == []

    def test_blank_entries_are_dropped(self):
        assert substantive_observables(["", "   "]) == []


def test_technique_names_from_the_lookup_reach_the_grounding_audit(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
) -> None:
    """The name-support check only works if the orchestrator carries the
    technique's ATT&CK names from the lookup into the audit."""
    mock_hecate.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1003.001",
        tactics=["credential-access"],
        platforms=["Windows"],
        found=True,
        name="Process Hollowing",
        parent_name="Process Injection",
    )
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti)

    result = orch.run_once()

    assert result.draft_path is not None
    content = result.draft_path.read_text()
    assert "nothing in the CTI or research describes 'Process Hollowing'" in content
