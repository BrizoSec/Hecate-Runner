"""CLI-level tests for `run`, `otx-poll`, `rss-poll`, `misp-poll`.

Uses typer's CliRunner against the real `app`, mocking the underlying
orchestrator/poller functions at the point cli.py imports them (not their
origin module -- cli.py does `from x import y`, which binds a local name).
Mirrors the pattern in test_cli_query_commands.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.cli import app
from hecate_runner.misp_poller import MispPollResult
from hecate_runner.orchestrator import RunResult
from hecate_runner.otx_poller import OtxPollResult
from hecate_runner.rss_poller import RssPollResult

runner = CliRunner()


@pytest.fixture
def cli_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for var in ["ATHF_WORKSPACE", "HECATE_RUNNER_MAX_DRAFTS_PER_DAY"]:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ATHF_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "4")
    return workspace


class TestRunCommand:
    def test_draft_created_exits_zero_and_prints_fields(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_orch = type(
            "FakeOrch",
            (),
            {
                "run_once": lambda self, dry_run=False: RunResult(
                    outcome="draft_created",
                    detail="some detail",
                    hunt_id="H-0001",
                    research_id="R-0001",
                    draft_path=Path("/tmp/H-0001.md"),
                )
            },
        )()
        monkeypatch.setattr(cli, "build_default_orchestrator", lambda settings: fake_orch)

        result = runner.invoke(app, ["run"])

        assert result.exit_code == 0
        assert "draft_created" in result.stdout
        assert "H-0001" in result.stdout
        assert "R-0001" in result.stdout

    def test_no_cti_exits_zero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_orch = type(
            "FakeOrch", (), {"run_once": lambda self, dry_run=False: RunResult(outcome="no_cti")}
        )()
        monkeypatch.setattr(cli, "build_default_orchestrator", lambda settings: fake_orch)

        result = runner.invoke(app, ["run"])

        assert result.exit_code == 0
        assert "no_cti" in result.stdout

    def test_athf_error_exits_nonzero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_orch = type(
            "FakeOrch",
            (),
            {
                "run_once": lambda self, dry_run=False: RunResult(
                    outcome="athf_error", detail="boom"
                )
            },
        )()
        monkeypatch.setattr(cli, "build_default_orchestrator", lambda settings: fake_orch)

        result = runner.invoke(app, ["run"])

        assert result.exit_code == 1
        assert "boom" in result.stdout

    def test_dry_run_flag_is_passed_through(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, bool] = {}

        fake_orch = type(
            "FakeOrch",
            (),
            {
                "run_once": lambda self, dry_run=False: (
                    captured.__setitem__("dry_run", dry_run),
                    RunResult(outcome="dry_run"),
                )[1]
            },
        )()
        monkeypatch.setattr(cli, "build_default_orchestrator", lambda settings: fake_orch)

        runner.invoke(app, ["run", "--dry-run"])

        assert captured["dry_run"] is True


class TestOtxPollCommand:
    def test_routed_pulse_exits_zero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli,
            "run_otx_poll",
            lambda settings: OtxPollResult(routed=1, routed_pulse_ids=["pulse-1"]),
        )

        result = runner.invoke(app, ["otx-poll"])

        assert result.exit_code == 0
        assert "pulse-1" in result.stdout

    def test_queue_occupied_shown(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli, "run_otx_poll", lambda settings: OtxPollResult(skipped_queue_occupied=True)
        )

        result = runner.invoke(app, ["otx-poll"])

        assert result.exit_code == 0
        assert "queue slot occupied" in result.stdout.lower()

    def test_error_exits_nonzero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli, "run_otx_poll", lambda settings: OtxPollResult(error="OTX_API_KEY is not set")
        )

        result = runner.invoke(app, ["otx-poll"])

        assert result.exit_code == 1
        assert "OTX_API_KEY" in result.stdout


class TestRssPollCommand:
    def test_routed_entry_exits_zero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli,
            "run_rss_poll",
            lambda settings: RssPollResult(routed=1, routed_entry_ids=["entry-1"]),
        )

        result = runner.invoke(app, ["rss-poll"])

        assert result.exit_code == 0
        assert "entry-1" in result.stdout

    def test_error_exits_nonzero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli, "run_rss_poll", lambda settings: RssPollResult(error="no feeds configured")
        )

        result = runner.invoke(app, ["rss-poll"])

        assert result.exit_code == 1
        assert "no feeds configured" in result.stdout


class TestMispPollCommand:
    def test_routed_event_exits_zero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli,
            "run_misp_poll",
            lambda settings: MispPollResult(routed=1, routed_event_uuids=["evt-1"]),
        )

        result = runner.invoke(app, ["misp-poll"])

        assert result.exit_code == 0
        assert "evt-1" in result.stdout

    def test_queue_occupied_shown(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli, "run_misp_poll", lambda settings: MispPollResult(skipped_queue_occupied=True)
        )

        result = runner.invoke(app, ["misp-poll"])

        assert result.exit_code == 0
        assert "queue slot occupied" in result.stdout.lower()

    def test_error_exits_nonzero(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            cli, "run_misp_poll", lambda settings: MispPollResult(error="MISP_BASE_URL is not set")
        )

        result = runner.invoke(app, ["misp-poll"])

        assert result.exit_code == 1
        assert "MISP_BASE_URL" in result.stdout
