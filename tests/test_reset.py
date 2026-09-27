"""`hecate-runner reset`: archive, then clear a workspace back to a blank state."""

from __future__ import annotations

import json
import os
import subprocess
import tarfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner import reset
from hecate_runner.cli import app
from hecate_runner.config import Settings

runner = CliRunner()
GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]


def _populate(ws: Path) -> None:
    """A workspace that has been running for a while."""
    q3 = ws / "hunts" / "2026" / "Q3"
    q3.mkdir(parents=True, exist_ok=True)
    (ws / "hunts" / "README.md").write_text("keep")
    (ws / "hunts" / "FORMAT_GUIDELINES.md").write_text("keep")
    (q3 / "H-0012.md").write_text("hunt")
    (ws / "hunts" / ".hunt_id_counter").write_text("12\n")
    (ws / "research").mkdir(exist_ok=True)
    (ws / "research" / "R-0009.md").write_text("research")
    (ws / "research" / ".research_id_counter").write_text('{"R-": 9}')
    (ws / "queries" / "H-0012").mkdir(parents=True)
    (ws / "queries" / "H-0012" / "rule.yml").write_text("title: x")
    (ws / "hecate_checkpoints.sqlite").write_text("db")
    (ws / "hecate_checkpoints.sqlite-wal").write_text("wal")
    (ws / ".orchestrator_state.json").write_text('{"drafts_today": 5}')
    (ws / ".pending_queries").mkdir()
    (ws / ".pending_queries" / "q.json").write_text("{}")
    for name in (
        ".otx_cursor_state.json",
        ".rss_cursor_state.json",
        ".multi_cti_cursor_state.json",
    ):
        (ws / name).write_text("{}")
    (ws / ".misp_cursor_state.json").write_text("{}")
    (ws / ".misp_cursor_state.json.pre-backfill.bak").write_text("{}")
    (ws / ".cursors").mkdir()
    (ws / ".cursors" / "abuse_ch_cursor.json").write_text("{}")
    (ws / "cti_queue" / "parked").mkdir(parents=True)
    (ws / "cti_queue" / "parked" / "p.json").write_text("{}")
    (ws / "cti_queue" / "processed").mkdir(parents=True, exist_ok=True)
    (ws / "cti_queue" / "processed" / "cti-1.txt").write_text("old")
    (ws / "cti_queue" / "next.txt").write_text("queued")
    (ws / "logs").mkdir(exist_ok=True)
    (ws / "logs" / "orchestrator.log").write_text("log")
    (ws / "logs" / "orchestrator.log.1").write_text("old log")
    (ws / "logs" / "stage_metrics.jsonl").write_text("{}")
    (ws / ".env").write_text("HECATE_LLM_PROVIDER=ollama\n")
    (ws / "knowledge").mkdir()
    (ws / "knowledge" / "environment.md").write_text("keep")


def _git_history(ws: Path, *committed: str) -> None:
    """Commit files that are then deleted, as a workspace's cleaned-up drafts are."""
    subprocess.run(["git", "init", "-q", str(ws)], check=True)
    for rel in committed:
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("old")
    subprocess.run([*GIT, "-C", str(ws), "add", "-A"], check=True)
    subprocess.run([*GIT, "-C", str(ws), "commit", "-qm", "history"], check=True)
    for rel in committed:
        (ws / rel).unlink()


def test_reset_clears_everything_a_run_produces(settings: Settings, workspace: Path) -> None:
    _populate(workspace)
    plan = reset.build_plan(settings, cwd=workspace)
    reset.execute(plan, settings)

    assert not list((workspace / "hunts").rglob("H-*.md"))
    assert not list((workspace / "research").glob("R-*.md"))
    assert list((workspace / "queries").iterdir()) == []
    assert not list(workspace.glob("hecate_checkpoints.sqlite*"))
    assert not (workspace / ".orchestrator_state.json").exists()
    assert not (workspace / ".pending_queries").exists()
    assert not list(workspace.glob(".*cursor_state.json*"))
    assert not (workspace / ".cursors").exists()
    assert list((workspace / "cti_queue").iterdir()) == []
    assert [p.name for p in (workspace / "logs").iterdir()] == ["orchestrator.log"]


def test_reset_keeps_configuration_and_knowledge(settings: Settings, workspace: Path) -> None:
    _populate(workspace)
    reset.execute(reset.build_plan(settings, cwd=workspace), settings)
    for kept in (
        "hunts/README.md",
        "hunts/FORMAT_GUIDELINES.md",
        ".env",
        "knowledge/environment.md",
    ):
        assert (workspace / kept).exists(), kept


def test_counters_restart_past_the_highest_id_in_git_history(
    settings: Settings, workspace: Path
) -> None:
    """H-0012 was never committed, so it is free again; H-0030 was, so it is not."""
    _populate(workspace)
    _git_history(workspace, "hunts/2026/Q2/H-0030.md", "research/R-0025.md")
    plan = reset.build_plan(settings, cwd=workspace)
    assert (plan.hunt_counter, plan.research_counter) == (30, 25)
    reset.execute(plan, settings)
    assert (workspace / "hunts" / ".hunt_id_counter").read_text() == "30\n"
    assert json.loads((workspace / "research" / ".research_id_counter").read_text()) == {"R-": 25}


def test_outside_git_numbering_restarts(settings: Settings, workspace: Path) -> None:
    _populate(workspace)
    plan = reset.build_plan(settings, cwd=workspace)
    assert not plan.git_repo
    reset.execute(plan, settings)
    assert (workspace / "hunts" / ".hunt_id_counter").read_text() == "0\n"


def test_staged_drafts_do_not_survive_in_the_git_index(settings: Settings, workspace: Path) -> None:
    """A staged-but-uncommitted hunt would be re-added by the next commit."""
    _populate(workspace)
    _git_history(workspace, "hunts/2026/Q2/H-0030.md")
    subprocess.run(["git", "-C", str(workspace), "add", "hunts", "research"], check=True)
    reset.execute(reset.build_plan(settings, cwd=workspace), settings)
    staged = subprocess.run(
        ["git", "-C", str(workspace), "diff", "--cached", "--name-only"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "H-0012" not in staged and "R-0009" not in staged


def test_keep_cursors_leaves_feed_position_alone(settings: Settings, workspace: Path) -> None:
    _populate(workspace)
    plan = reset.build_plan(settings, keep_cursors=True, cwd=workspace)
    reset.execute(plan, settings)
    assert (workspace / ".otx_cursor_state.json").exists()
    assert (workspace / ".cursors" / "abuse_ch_cursor.json").exists()
    assert not (workspace / ".orchestrator_state.json").exists()


def test_archive_holds_everything_removed_and_is_owner_only(
    settings: Settings, workspace: Path, tmp_path: Path
) -> None:
    _populate(workspace)
    plan = reset.build_plan(settings, cwd=workspace)
    target = reset.archive(plan, tmp_path / "archives")
    assert target.stat().st_mode & 0o777 == 0o600
    with tarfile.open(target) as tar:
        names = tar.getnames()
    for expected in ("H-0012.md", "R-0009.md", "rule.yml", ".orchestrator_state.json", "p.json"):
        assert any(n.endswith(expected) for n in names), expected


# --- CLI ---------------------------------------------------------------------------------


@pytest.fixture
def cli_workspace(workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)  # away from the repo's real .env
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setattr(reset, "running_hecate_processes", lambda: [])
    _populate(workspace)
    return workspace


def test_cli_reset_with_yes_archives_then_clears(cli_workspace: Path) -> None:
    result = runner.invoke(app, ["reset", "--yes"])
    assert result.exit_code == 0, result.output
    assert "Workspace reset" in result.output
    assert "H-0001" in result.output  # not a git repo, so numbering restarts
    assert not (cli_workspace / ".orchestrator_state.json").exists()
    assert list(cli_workspace.parent.glob("hecate-reset-archive-*.tar.gz"))


def test_cli_reset_declined_changes_nothing(cli_workspace: Path) -> None:
    result = runner.invoke(app, ["reset"], input="n\n")
    assert result.exit_code == 0
    assert "Nothing changed" in result.output
    assert (cli_workspace / ".orchestrator_state.json").exists()
    assert not list(cli_workspace.parent.glob("hecate-reset-archive-*.tar.gz"))


def test_cli_reset_refuses_while_hecate_is_running(
    cli_workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        reset, "running_hecate_processes", lambda: ["4242: python hecate-runner run"]
    )
    result = runner.invoke(app, ["reset", "--yes"])
    assert result.exit_code == 1
    assert "Refusing to reset" in result.output
    assert (cli_workspace / ".orchestrator_state.json").exists()


def test_cli_reset_no_archive_writes_no_tarball(cli_workspace: Path) -> None:
    result = runner.invoke(app, ["reset", "--yes", "--no-archive"])
    assert result.exit_code == 0, result.output
    assert not list(cli_workspace.parent.glob("hecate-reset-archive-*.tar.gz"))


def test_reset_leaves_an_empty_log_owned_by_the_caller(settings: Settings, workspace: Path) -> None:
    """systemd's append: creates a missing log root-owned, which the Runner then
    cannot open; a reset must not leave the path missing."""
    _populate(workspace)
    reset.execute(reset.build_plan(settings, cwd=workspace), settings)
    assert settings.log_file.exists()
    assert settings.log_file.read_text() == ""
    assert settings.log_file.stat().st_uid == os.getuid()
