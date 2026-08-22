"""CLI-level tests for the propose/pending/approve/reject commands.

Uses typer's CliRunner against the real `app` so these exercise the actual
command wiring (argument parsing, Settings() construction, exit codes) --
not just the underlying query_execution/query_store modules, which have
their own focused unit tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.query_store import PendingQueryStore

runner = CliRunner()


@pytest.fixture
def cli_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI's own Settings() at the fake workspace, like `settings` does."""
    for var in ["ATHF_WORKSPACE", "HECATE_RUNNER_QUERY_PROVIDER", "HECATE_RUNNER_MAX_DRAFTS_PER_DAY"]:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ATHF_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "4")
    return workspace


def test_propose_stages_a_valid_query(cli_env: Path) -> None:
    result = runner.invoke(
        app,
        [
            "propose",
            "H-0001",
            "--query",
            "index=main | head 10",
            "--data-source",
            "splunk",
            "--time-range-days",
            "7",
            "--limit",
            "100",
        ],
    )
    assert result.exit_code == 0
    assert "staged" in result.output.lower()

    store = PendingQueryStore(cli_env / ".pending_queries")
    staged = store.load("H-0001")
    assert staged is not None
    assert staged.query_text == "index=main | head 10"


def test_propose_rejects_unbounded_query(cli_env: Path) -> None:
    result = runner.invoke(
        app,
        [
            "propose",
            "H-0002",
            "--query",
            "index=*",
            "--data-source",
            "splunk",
            "--time-range-days",
            "365",
            "--limit",
            "999999",
        ],
    )
    assert result.exit_code == 1
    assert "guardrail violation" in result.output.lower()

    store = PendingQueryStore(cli_env / ".pending_queries")
    assert store.load("H-0002") is None


def test_pending_shows_staged_queries(cli_env: Path) -> None:
    store = PendingQueryStore(cli_env / ".pending_queries")
    from hecate_runner.query_execution import ProposedQuery

    store.save(
        ProposedQuery(
            hunt_id="H-0003", data_source="splunk", query_text="index=main", time_range_days=7, limit=100
        )
    )

    result = runner.invoke(app, ["pending"])
    assert result.exit_code == 0
    assert "H-0003" in result.output


def test_pending_empty_says_so(cli_env: Path) -> None:
    result = runner.invoke(app, ["pending"])
    assert result.exit_code == 0
    assert "no queries pending" in result.output.lower()


def test_approve_missing_hunt_fails(cli_env: Path) -> None:
    result = runner.invoke(app, ["approve", "H-9999", "--yes"])
    assert result.exit_code == 1
    assert "no pending query" in result.output.lower()


def test_approve_executes_via_mock_and_clears_pending(cli_env: Path) -> None:
    runner.invoke(
        app,
        [
            "propose",
            "H-0004",
            "--query",
            "index=main | head 10",
            "--data-source",
            "splunk",
            "--time-range-days",
            "7",
            "--limit",
            "100",
        ],
    )

    result = runner.invoke(app, ["approve", "H-0004", "--yes"])
    assert result.exit_code == 0
    assert "executed" in result.output.lower()

    store = PendingQueryStore(cli_env / ".pending_queries")
    assert store.load("H-0004") is None


def test_approve_without_yes_prompts_and_cancel_leaves_it_staged(cli_env: Path) -> None:
    runner.invoke(
        app,
        [
            "propose",
            "H-0005",
            "--query",
            "index=main",
            "--data-source",
            "splunk",
            "--time-range-days",
            "7",
            "--limit",
            "100",
        ],
    )

    result = runner.invoke(app, ["approve", "H-0005"], input="n\n")
    assert result.exit_code == 1
    assert "cancelled" in result.output.lower()

    store = PendingQueryStore(cli_env / ".pending_queries")
    assert store.load("H-0005") is not None


def test_approve_rechecks_guardrails_against_current_config(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.invoke(
        app,
        [
            "propose",
            "H-0006",
            "--query",
            "index=main",
            "--data-source",
            "splunk",
            "--time-range-days",
            "7",
            "--limit",
            "100",
        ],
    )

    # Tighten the ceiling after proposing but before approving.
    monkeypatch.setenv("HECATE_RUNNER_MAX_QUERY_TIME_RANGE_DAYS", "1")

    result = runner.invoke(app, ["approve", "H-0006", "--yes"])
    assert result.exit_code == 1
    assert "guardrail violation" in result.output.lower()

    # Left staged for the human to fix or reject, not silently dropped.
    store = PendingQueryStore(cli_env / ".pending_queries")
    assert store.load("H-0006") is not None


def test_reject_discards_staged_query(cli_env: Path) -> None:
    runner.invoke(
        app,
        [
            "propose",
            "H-0007",
            "--query",
            "index=main",
            "--data-source",
            "splunk",
            "--time-range-days",
            "7",
            "--limit",
            "100",
        ],
    )

    result = runner.invoke(app, ["reject", "H-0007", "--reason", "not needed"])
    assert result.exit_code == 0
    assert "rejected" in result.output.lower()

    store = PendingQueryStore(cli_env / ".pending_queries")
    assert store.load("H-0007") is None


def test_reject_missing_hunt_fails(cli_env: Path) -> None:
    result = runner.invoke(app, ["reject", "H-9999"])
    assert result.exit_code == 1
