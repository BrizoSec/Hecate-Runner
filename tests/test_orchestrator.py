"""Orchestrator loop tests. Uses mocks for AthfClient so no real athf runs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sec7669.athf_client import AthfClient, AthfError, HypothesisResult, ResearchResult
from sec7669.config import Settings
from sec7669.cti import FileQueueProvider
from sec7669.orchestrator import Orchestrator, derive_research_topic


@pytest.fixture
def mock_athf(
    sample_hypothesis: HypothesisResult,
    sample_research_result: ResearchResult,
) -> MagicMock:
    mock = MagicMock(spec=AthfClient)
    mock.hypothesis_generator.return_value = sample_hypothesis
    mock.research_new.return_value = sample_research_result
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
    monkeypatch.setenv("SEC7669_MAX_DRAFTS_PER_DAY", "1")
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
    monkeypatch.setenv("SEC7669_RESEARCH_ENABLED", "false")
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

    from sec7669.state import OrchestratorState
    state = OrchestratorState.load(settings.state_file)
    assert state.drafts_today == 0


def test_research_failure_does_not_notify(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    mock_athf.research_new.side_effect = AthfError("ollama timed out")
    notify = MagicMock()

    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=notify)
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


def test_notify_called_on_draft_created(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_athf: MagicMock,
) -> None:
    notify = MagicMock()
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=notify)
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
    orch = Orchestrator(settings=settings, athf=mock_athf, cti_provider=file_queue_with_cti, notify=notify)
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

    from sec7669.state import OrchestratorState
    state = OrchestratorState.load(settings.state_file)
    assert state.drafts_today == 1
    assert state.total_drafts_ever == 1
    assert state.last_run_iso != ""
    assert state.consecutive_failures == 0
