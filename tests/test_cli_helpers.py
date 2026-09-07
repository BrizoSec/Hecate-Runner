"""Tests for standalone helper functions in hecate-runner.cli.

Full command coverage for cli.py (Typer app) isn't attempted here — this only
covers the pure-function helpers that have real branching logic worth
protecting.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from hecate_runner.cli import _effective_model, _stdout_already_targets, _tavily_key_available
from hecate_runner.config import Settings


def test_tavily_key_from_process_env(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-key")
    assert _tavily_key_available(settings) is True


def test_tavily_key_from_workspace_env_file(
    settings: Settings, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    (workspace / ".env").write_text("TAVILY_API_KEY=tvly-from-workspace-file\n")
    assert _tavily_key_available(settings) is True


def test_tavily_key_absent_from_both(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    # workspace fixture doesn't create a .env file by default
    assert _tavily_key_available(settings) is False


def test_workspace_env_file_present_but_no_tavily_key(
    settings: Settings, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    (workspace / ".env").write_text("ATHF_LLM_PROVIDER=ollama\n")
    assert _tavily_key_available(settings) is False


# Under systemd, StandardOutput=append:<same log file> makes stdout point at
# the log file before the process even starts. _configure_logging used to
# unconditionally add both a FileHandler(log_file) and a
# StreamHandler(sys.stdout) -- when stdout is already that same file, both
# handlers write to it and every real production log line appears twice.
# Observed directly in logs/orchestrator.log under the actual systemd unit.
def test_stdout_targets_same_file_as_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_file = tmp_path / "orchestrator.log"
    with open(log_file, "a") as f:
        monkeypatch.setattr(sys, "stdout", f)
        assert _stdout_already_targets(log_file) is True


def test_stdout_targets_different_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log_file = tmp_path / "orchestrator.log"
    log_file.write_text("")
    other_file = tmp_path / "something-else.log"
    with open(other_file, "a") as f:
        monkeypatch.setattr(sys, "stdout", f)
        assert _stdout_already_targets(log_file) is False


def test_stdout_target_check_missing_log_file_is_false_not_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_file = tmp_path / "does-not-exist.log"
    scratch = tmp_path / "scratch"
    with open(scratch, "a") as f:
        monkeypatch.setattr(sys, "stdout", f)
        assert _stdout_already_targets(log_file) is False


def test_stdout_target_check_non_file_stdout_is_false_not_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Interactive/pytest-captured stdout often has no real fileno() at all
    # (e.g. io.StringIO) -- must degrade to False, not raise.
    import io

    log_file = tmp_path / "orchestrator.log"
    log_file.write_text("")
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    assert _stdout_already_targets(log_file) is False


def test_effective_model_reads_the_workspace_when_unset(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLM choice lives in the workspace .env by default, so `status` has to
    look there -- printing a placeholder would answer a different question
    than "what will actually run"."""
    monkeypatch.delenv("ATHF_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ATHF_LLM_MODEL", raising=False)
    (settings.athf_workspace / ".env").write_text(
        "ATHF_LLM_PROVIDER=ollama\nATHF_LLM_MODEL=qwen2.5:14b-instruct-q4_K_M\n"
    )
    rendered = _effective_model(settings)
    assert "ollama:qwen2.5:14b-instruct-q4_K_M" in rendered
    assert "from workspace" in rendered


def test_effective_model_marks_an_explicit_override(settings: Settings) -> None:
    settings_with_override = settings.model_copy(
        update={"athf_llm_provider": "ollama", "athf_llm_model": "llama3"}
    )
    rendered = _effective_model(settings_with_override)
    assert rendered.startswith("ollama:llama3")
    assert "from workspace" not in rendered


def test_effective_model_when_nothing_is_configured(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ATHF_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ATHF_LLM_MODEL", raising=False)
    workspace_env = settings.athf_workspace / ".env"
    if workspace_env.exists():
        workspace_env.unlink()
    assert "autodetect" in _effective_model(settings)
