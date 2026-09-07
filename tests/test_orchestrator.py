"""Orchestrator loop tests. Uses mocks for AthfClient so no real athf runs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.athf_client import (
    AthfClient,
    AthfError,
    HypothesisResult,
    ResearchResult,
    TechniqueMetadata,
)
from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.orchestrator import Orchestrator, derive_research_topic, has_narrative


@pytest.fixture
def mock_athf(
    sample_hypothesis: HypothesisResult,
    sample_research_result: ResearchResult,
) -> MagicMock:
    mock = MagicMock(spec=AthfClient)
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
    return mock


def test_no_cti_returns_no_cti(
    settings: Settings,
    workspace: Path,
    mock_athf: MagicMock,
) -> None:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=provider)

    result = orch.run_once()
    assert result.outcome == "no_cti"
    mock_athf.hypothesis_generator.assert_not_called()


def test_happy_path_creates_draft(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    workspace: Path,
) -> None:
    orch = Orchestrator(
        settings=settings,
        athf=mock_athf,
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

    mock_athf.research_new.assert_called_once()
    mock_athf.hypothesis_generator.assert_called_once()
    # research_id from the grounding step must flow into hypothesis generation
    assert mock_athf.hypothesis_generator.call_args.kwargs["research_id"] == "R-0001"


def test_parseable_indicator_dump_skips_research_and_llm(
    settings: Settings,
    workspace: Path,
    mock_athf: MagicMock,
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
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "draft_created"
    mock_athf.research_new.assert_not_called()
    # A readable indicator inventory means the draft is built directly, with
    # no LLM call at all -- there is no slot left for the model to invent a
    # delivery vector or technique into.
    mock_athf.hypothesis_generator.assert_not_called()
    assert result.research_id is None


def test_narrative_free_cti_without_readable_inventory_falls_back_to_llm(
    settings: Settings,
    workspace: Path,
    mock_athf: MagicMock,
) -> None:
    """`has_narrative` is a heuristic over provider blurb formats. When it
    says "no narrative" but there's no indicator inventory to confirm the
    source really is a feed dump, building a template draft would discard
    real CTI -- so the LLM path runs instead, with the constraint applied."""
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "MISP Event: Something unusual\nOrg: SomeOrg\nThreat Level: High"
    )
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=provider)

    result = orch.run_once()

    assert result.outcome == "draft_created"
    assert mock_athf.hypothesis_generator.call_args.kwargs["indicators_only"] is True
    # Research still runs on this path (the draft needs grounding), so the
    # web-search guard is what prevents the wrong-dated-aggregator fabrication
    # here -- the parseable-dump test above no longer covers it.
    assert mock_athf.research_new.call_args.kwargs["web_search_enabled"] is False


def test_indicator_dump_draft_has_no_techniques_and_no_invented_behavior(
    settings: Settings,
    workspace: Path,
    mock_athf: MagicMock,
) -> None:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "MISP Event: ThreatFox IOCs for 2026-08-09\n"
        "Org: abuse.ch\n"
        "Attributes (245 total): domain (146), ip-dst|port (78), url (21)"
    )
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=provider)

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
    mock_athf: MagicMock,
) -> None:
    (file_queue_with_cti.queue_dir / "next.txt").write_text(
        "RSS: Some Campaign\n"
        "Source: example.com\n"
        "Summary: Attackers observed doing something specific and narrative-worthy.\n"
        "Link: https://example.com/post"
    )
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)

    orch.run_once()

    assert mock_athf.research_new.call_args.kwargs["web_search_enabled"] is True
    assert mock_athf.hypothesis_generator.call_args.kwargs["indicators_only"] is False


def test_related_hunts_from_research_flow_into_draft(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    sample_research_result: ResearchResult,
) -> None:
    # A research step that found related past hunts (see
    # HuntResearcherAgent._skill_4_related_work in athf) must actually land
    # in the draft's related_hunts frontmatter, not the hardcoded [] this
    # regression-tests against.
    mock_athf.research_new.return_value = ResearchResult(
        research_id=sample_research_result.research_id,
        recommended_hypothesis=sample_research_result.recommended_hypothesis,
        related_hunts=["H-0602", "H-0578"],
    )
    orch = Orchestrator(
        settings=settings,
        athf=mock_athf,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()

    assert result.outcome == "draft_created"
    content = result.draft_path.read_text()
    assert 'related_hunts: ["H-0602", "H-0578"]' in content


def test_dry_run_does_not_call_athf(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    workspace: Path,
) -> None:
    orch = Orchestrator(
        settings=settings,
        athf=mock_athf,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once(dry_run=True)
    assert result.outcome == "dry_run"
    mock_athf.research_new.assert_not_called()
    mock_athf.hypothesis_generator.assert_not_called()
    # CTI stays in the queue
    assert (workspace / "cti_queue" / "next.txt").exists()


def test_quota_enforcement(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "1")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    orch = Orchestrator(
        settings=settings,
        athf=mock_athf,
        cti_provider=file_queue_with_cti,
    )
    first = orch.run_once()
    assert first.outcome == "draft_created"

    # Put a second CTI in and try again
    (workspace / "cti_queue" / "next.txt").write_text("another intel")
    second = orch.run_once()
    assert second.outcome == "quota_reached"
    # Ensure hypothesis-generator only called once
    assert mock_athf.hypothesis_generator.call_count == 1


def test_athf_error_refunds_quota(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    sample_research_result: ResearchResult,
) -> None:
    failing_athf = MagicMock(spec=AthfClient)
    failing_athf.research_new.return_value = sample_research_result
    failing_athf.hypothesis_generator.side_effect = AthfError("simulated failure")

    orch = Orchestrator(
        settings=settings,
        athf=failing_athf,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()
    assert result.outcome == "athf_error"
    # CTI stays in queue for retry
    assert (workspace / "cti_queue" / "next.txt").exists()


def test_write_failure_refunds_quota_and_leaves_cti_queued(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    mock_athf: MagicMock,
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

    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    assert result.outcome == "write_error"
    # CTI stays in queue for retry -- it was never acknowledged.
    assert (workspace / "cti_queue" / "next.txt").exists()


def test_acknowledge_failure_does_not_fail_the_cycle_or_refund_quota(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    workspace: Path,
    mock_athf: MagicMock,
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
        athf=mock_athf,
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
    empty_athf = MagicMock(spec=AthfClient)
    empty_athf.research_new.return_value = sample_research_result
    empty_athf.hypothesis_generator.return_value = HypothesisResult()

    orch = Orchestrator(
        settings=settings,
        athf=empty_athf,
        cti_provider=file_queue_with_cti,
    )
    result = orch.run_once()
    assert result.outcome == "empty_hypothesis"


def test_research_disabled_skips_research_call(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HECATE_RUNNER_RESEARCH_ENABLED", "false")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    assert result.outcome == "draft_created"
    assert result.research_id is None
    mock_athf.research_new.assert_not_called()
    assert mock_athf.hypothesis_generator.call_args.kwargs["research_id"] is None


def test_research_failure_aborts_cycle(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    workspace: Path,
) -> None:
    mock_athf.research_new.side_effect = AthfError("ollama timed out")

    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    # Cold generation is unreliable (~30% accuracy on known-answer fixtures),
    # so a grounding failure must refuse to fall back to an ungrounded draft.
    assert result.outcome == "research_error"
    assert result.research_id is None
    assert result.draft_path is None
    assert not result.ok
    mock_athf.hypothesis_generator.assert_not_called()

    # Quota refunded and CTI left in queue for retry, same as any other failure.
    assert (workspace / "cti_queue" / "next.txt").exists()

    from hecate_runner.state import OrchestratorState

    state = OrchestratorState.load(settings.state_file)
    assert state.drafts_today == 0


def test_research_failure_does_not_notify(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    mock_athf.research_new.side_effect = AthfError("ollama timed out")
    notify = MagicMock()

    orch = Orchestrator(
        settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=notify
    )
    orch.run_once()

    notify.assert_not_called()


def test_research_empty_result_aborts_cycle(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    mock_athf.research_new.return_value = ResearchResult()  # empty research_id

    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)
    result = orch.run_once()

    assert result.outcome == "research_empty"
    assert result.research_id is None
    assert not result.ok
    mock_athf.hypothesis_generator.assert_not_called()


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
    # MISP's _event_to_blurb never includes a narrative field -- only
    # Org/Threat Level/TLP/Tags/attribute counts -- so a MISP-sourced item
    # like a ThreatFox IOC-dump event is structurally narrative-free.
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
    mock_athf: MagicMock,
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
    mock_athf.lookup_technique.side_effect = lambda technique_id, timeout_sec: (
        broad if technique_id == "T1078" else narrow
    )
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)

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
    mock_athf: MagicMock,
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
    mock_athf.lookup_technique.return_value = pre_compromise
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)

    _, platforms = orch._resolve_ttps(["T1598"])

    assert platforms == ["Pre-Compromise (reconnaissance/targeting -- not endpoint/OS-specific)"]


def test_resolve_ttps_falls_back_to_empty_platforms_when_all_techniques_are_broad(
    settings: Settings,
    mock_athf: MagicMock,
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
    mock_athf.lookup_technique.return_value = broad
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)

    _, platforms = orch._resolve_ttps(["T1078"])

    assert platforms == []


def test_notify_called_on_draft_created(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    notify = MagicMock()
    orch = Orchestrator(
        settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=notify
    )
    result = orch.run_once()

    notify.assert_called_once()
    (notified_result,) = notify.call_args.args
    assert notified_result.outcome == "draft_created"
    assert notified_result.hunt_id == result.hunt_id


def test_notify_not_called_when_no_cti(
    settings: Settings,
    workspace: Path,
    mock_athf: MagicMock,
) -> None:
    notify = MagicMock()
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=provider, notify=notify)
    orch.run_once()

    notify.assert_not_called()


def test_notify_not_called_on_dry_run(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    notify = MagicMock()
    orch = Orchestrator(
        settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=notify
    )
    orch.run_once(dry_run=True)

    notify.assert_not_called()


def test_notify_failure_does_not_corrupt_successful_outcome(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    def failing_notify(result: object) -> None:
        raise RuntimeError("slack is down")

    orch = Orchestrator(
        settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=failing_notify
    )
    result = orch.run_once()

    # A raising notifier must not turn a successful draft into an error outcome.
    assert result.outcome == "draft_created"
    assert result.hunt_id is not None


def test_orchestrator_without_notify_arg_defaults_to_noop(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti)
    result = orch.run_once()
    assert result.outcome == "draft_created"


def test_state_persists_across_runs(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
    workspace: Path,
) -> None:
    orch = Orchestrator(
        settings=settings,
        athf=mock_athf,
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
