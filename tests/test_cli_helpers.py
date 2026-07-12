"""Tests for standalone helper functions in sec7669.cli.

Full command coverage for cli.py (Typer app) isn't attempted here — this only
covers the pure-function helpers that have real branching logic worth
protecting.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sec7669.cli import _tavily_key_available
from sec7669.config import Settings


def test_tavily_key_from_process_env(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-key")
    assert _tavily_key_available(settings) is True


def test_tavily_key_from_workspace_env_file(
    settings: Settings, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    (workspace / ".env").write_text("TAVILY_API_KEY=tvly-from-workspace-file\n")
    assert _tavily_key_available(settings) is True


def test_tavily_key_absent_from_both(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    # workspace fixture doesn't create a .env file by default
    assert _tavily_key_available(settings) is False


def test_workspace_env_file_present_but_no_tavily_key(
    settings: Settings, workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    (workspace / ".env").write_text("ATHF_LLM_PROVIDER=ollama\n")
    assert _tavily_key_available(settings) is False
