"""Tests for hecate-runner.config.Settings."""

from __future__ import annotations

from pathlib import Path

import pytest

from hecate_runner.config import Settings


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in list(monkeypatch._setenv.keys()) if hasattr(monkeypatch, "_setenv") else []:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ATHF_WORKSPACE", "/tmp/athf")

    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.athf_workspace == Path("/tmp/athf").resolve()
    assert s.max_drafts_per_day == 4
    assert s.cti_provider == "file"
    assert s.log_level == "INFO"


def test_derived_paths(settings: Settings, workspace: Path) -> None:
    assert settings.athf_bin_resolved == workspace / ".venv" / "bin" / "athf"
    assert settings.cti_queue_dir_resolved == workspace / "cti_queue"
    assert settings.cti_next_file == workspace / "cti_queue" / "next.txt"
    assert settings.hunts_root == workspace / "hunts"
    assert settings.state_file == workspace / ".orchestrator_state.json"


def test_env_for_athf(settings: Settings) -> None:
    env = settings.env_for_athf()
    assert env["ATHF_LLM_PROVIDER"] == "ollama"
    assert env["ATHF_LLM_MODEL"].startswith("qwen")
    assert "ATHF_WORKSPACE" in env


def test_max_drafts_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATHF_WORKSPACE", "/tmp/athf")
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "0")
    with pytest.raises(Exception):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_workspace_expansion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATHF_WORKSPACE", "~/athf")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert not str(s.athf_workspace).startswith("~")


def test_redacted_dict_masks_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATHF_WORKSPACE", "/tmp/athf")
    monkeypatch.setenv("OTX_API_KEY", "super-secret-otx-key")
    monkeypatch.setenv("HECATE_RUNNER_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/super/secret/path")
    s = Settings(_env_file=None)  # type: ignore[call-arg]

    dumped = s.redacted_dict()
    assert dumped["otx_api_key"] == "<redacted>"
    assert dumped["slack_webhook_url"] == "<redacted>"
    assert "super-secret-otx-key" not in str(dumped)
    assert "hooks.slack.com" not in str(dumped)


def test_redacted_dict_leaves_unset_secrets_as_none(settings: Settings) -> None:
    dumped = settings.redacted_dict()
    assert dumped["otx_api_key"] is None
    assert dumped["slack_webhook_url"] is None


def test_redacted_dict_does_not_touch_non_secret_fields(settings: Settings) -> None:
    dumped = settings.redacted_dict()
    assert dumped["max_drafts_per_day"] == settings.max_drafts_per_day
    assert dumped["cti_provider"] == settings.cti_provider
