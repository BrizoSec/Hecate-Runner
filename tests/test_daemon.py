"""Tests for `hecate-runner daemon` command."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.cli import app
from hecate_runner.orchestrator import RunResult

runner = CliRunner()


@pytest.fixture
def cli_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr("hecate_runner.integration_checks.start_health_refresh", lambda _: None)
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "10")
    monkeypatch.setenv("HECATE_RUNNER_DAEMON_INTERVAL_SEC", "1")
    return workspace


class TestDaemonCommand:
    def test_daemon_max_cycles_runs_and_exits_zero(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        class FakeOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                nonlocal call_count
                call_count += 1
                return RunResult(
                    outcome="drafted",
                    detail="draft created",
                    hunt_id=f"H-000{call_count}",
                    research_id=f"R-000{call_count}",
                    draft_path=Path(f"/tmp/H-000{call_count}.md"),
                )

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: FakeOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "2", "--interval", "1"])
        assert result.exit_code == 0
        assert call_count == 2
        assert "Reached max cycles (2). Exiting daemon." in result.output
        assert "Hecate daemon shut down gracefully after 2 cycles." in result.output

    def test_daemon_handles_empty_queue(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        call_count = 0

        class FakeOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                nonlocal call_count
                call_count += 1
                return RunResult(outcome="empty", detail="Queue empty")

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: FakeOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "1", "--interval", "1"])
        assert result.exit_code == 0
        assert call_count == 1
        assert "Outcome: empty" in result.output

    def test_daemon_fatal_exception_exits_one(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class CrashingOrch:
            def run_once(self, dry_run: bool = False) -> RunResult:
                raise RuntimeError("Disk corrupted")

        monkeypatch.setattr(
            cli, "build_default_orchestrator", lambda s, ignore_quota=False: CrashingOrch()
        )

        result = runner.invoke(app, ["daemon", "--max-cycles", "1"])
        assert result.exit_code == 1
        assert "Fatal daemon exception: Disk corrupted" in result.output
