"""Tests for hecate-runner.state.OrchestratorState."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.state import OrchestratorState


def test_load_missing_file(tmp_path: Path) -> None:
    state = OrchestratorState.load(tmp_path / "state.json")
    assert state.drafts_today == 0
    assert state.total_drafts_ever == 0
    assert state.date == ""


def test_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = OrchestratorState(drafts_today=3, total_drafts_ever=17, date="2026-07-04")
    state.save(path)
    loaded = OrchestratorState.load(path)
    assert loaded.drafts_today == 3
    assert loaded.total_drafts_ever == 17


def test_load_corrupt_resets(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("not json at all")
    state = OrchestratorState.load(path)
    assert state.drafts_today == 0


def test_check_and_reserve_under_quota() -> None:
    state = OrchestratorState()
    assert state.check_and_reserve_draft(max_per_day=3) is True
    assert state.drafts_today == 1
    assert state.total_drafts_ever == 1


def test_check_and_reserve_at_quota() -> None:
    state = OrchestratorState(
        date=datetime.now(UTC).strftime("%Y-%m-%d"),
        drafts_today=3,
    )
    assert state.check_and_reserve_draft(max_per_day=3) is False
    assert state.drafts_today == 3  # unchanged


def test_check_and_reserve_rolls_over_day() -> None:
    state = OrchestratorState(date="1999-01-01", drafts_today=99)
    assert state.check_and_reserve_draft(max_per_day=4) is True
    assert state.drafts_today == 1
    assert state.date == datetime.now(UTC).strftime("%Y-%m-%d")


def test_check_and_reserve_research_caps_and_rolls_over() -> None:
    state = OrchestratorState(date="1999-01-01", drafts_today=2, research_runs_today=9)
    assert state.check_and_reserve_research(max_per_day=1) is True
    assert state.research_runs_today == 1
    assert state.drafts_today == 0
    assert state.check_and_reserve_research(max_per_day=1) is False
    assert state.research_runs_today == 1


def test_mark_run_success_clears_failures() -> None:
    state = OrchestratorState(consecutive_failures=5)
    state.mark_run(success=True)
    assert state.consecutive_failures == 0
    assert state.last_run_iso != ""


def test_mark_run_failure_increments() -> None:
    state = OrchestratorState()
    state.mark_run(success=False)
    state.mark_run(success=False)
    assert state.consecutive_failures == 2


def test_check_spacing() -> None:
    from datetime import timedelta

    state = OrchestratorState()
    # No last draft -> satisfied
    assert state.check_spacing(min_hours=6.0) == (True, 0.0)

    # Disabled (0 hours) -> satisfied
    state.last_draft_iso = datetime.now(UTC).isoformat()
    assert state.check_spacing(min_hours=0.0) == (True, 0.0)

    # Just drafted now -> cooldown active
    spaced, elapsed = state.check_spacing(min_hours=6.0)
    assert spaced is False
    assert elapsed < 0.1

    # Drafted 7 hours ago -> satisfied
    past = (datetime.now(UTC) - timedelta(hours=7)).isoformat()
    state.last_draft_iso = past
    assert state.check_spacing(min_hours=6.0) == (True, 0.0)
