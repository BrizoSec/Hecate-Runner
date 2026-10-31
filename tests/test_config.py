"""Tests for hecate-runner.config.Settings."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from hecate_runner.config import Settings


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in list(monkeypatch._setenv.keys()) if hasattr(monkeypatch, "_setenv") else []:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HECATE_WORKSPACE", "/tmp/hecate")

    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.hecate_workspace == Path("/tmp/hecate").resolve()
    assert s.max_drafts_per_day == 2
    assert s.max_research_runs_per_day == 3
    assert s.min_hours_between_drafts == 6.0
    assert s.cti_provider == "file"
    assert s.log_level == "INFO"


def test_derived_paths(settings: Settings, workspace: Path) -> None:
    assert settings.hecate_bin_resolved == workspace / ".venv" / "bin" / "hecate-agent"
    assert settings.cti_queue_dir_resolved == workspace / "cti_queue"
    assert settings.cti_next_file == workspace / "cti_queue" / "next.txt"
    assert settings.hunts_root == workspace / "hunts"
    assert settings.state_file == workspace / ".orchestrator_state.json"


def test_env_for_hecate_omits_unset_llm_keys(settings: Settings) -> None:
    """Anything passed here overrides the workspace's own .env (hecate loads it
    with override=False), so unset keys must not be passed at all -- otherwise
    the workspace can never own its LLM choice."""
    env = settings.env_for_hecate()
    assert "HECATE_WORKSPACE" in env
    assert "HECATE_LLM_PROVIDER" not in env
    assert "HECATE_LLM_MODEL" not in env


def test_env_for_hecate_names_the_live_call_log(settings: Settings) -> None:
    # Core writes each model call there as it happens; the monitor reads it mid-cycle.
    assert settings.env_for_hecate()["HECATE_LLM_CALL_LOG"] == str(settings.llm_calls_file)
    assert settings.llm_calls_file.parent == settings.log_dir


def test_env_for_hecate_passes_explicit_llm_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", "/tmp/hecate")
    monkeypatch.setenv("HECATE_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("HECATE_LLM_MODEL", "qwen2.5:14b-instruct-q4_K_M")
    env = Settings(_env_file=None).env_for_hecate()  # type: ignore[call-arg]
    assert env["HECATE_LLM_PROVIDER"] == "ollama"
    assert env["HECATE_LLM_MODEL"] == "qwen2.5:14b-instruct-q4_K_M"


def test_max_drafts_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", "/tmp/hecate")
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_workspace_expansion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", "~/hecate")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert not str(s.hecate_workspace).startswith("~")


def test_redacted_dict_masks_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_WORKSPACE", "/tmp/hecate")
    monkeypatch.setenv("OTX_API_KEY", "super-secret-otx-key")
    monkeypatch.setenv("CALDERA_API_KEY", "test-secret-caldera-key")
    monkeypatch.setenv(
        "HECATE_RUNNER_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/super/secret/path"
    )
    s = Settings(_env_file=None)  # type: ignore[call-arg]

    dumped = s.redacted_dict()
    assert dumped["otx_api_key"] == "<redacted>"
    assert dumped["slack_webhook_url"] == "<redacted>"
    assert dumped["caldera_api_key"] == "<redacted>"
    assert "test-secret-caldera-key" not in str(dumped)
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


def test_misp_org_allowlist_defaults_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HECATE_RUNNER_MISP_ORG_ALLOWLIST", raising=False)
    assert Settings(_env_file=None).misp_org_allowlist == []


def test_misp_org_allowlist_parses_and_trims(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HECATE_RUNNER_MISP_ORG_ALLOWLIST", " CIRCL , CUDESO ,, ESET ")
    assert Settings(_env_file=None).misp_org_allowlist == ["CIRCL", "CUDESO", "ESET"]


def test_shared_settings_cannot_publish_to_live_services(settings: Settings) -> None:
    assert not settings.github_publishing_enabled
    assert not settings.misp_publishing_enabled
    assert settings.github_app_id is None
    assert settings.github_installation_id is None
    assert settings.github_app_private_key_path is None


def test_local_dotenv_cannot_enable_publication_during_tests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED=true\nHECATE_RUNNER_MISP_PUBLISHING_ENABLED=true\n"
    )
    config = Settings()
    assert not config.github_publishing_enabled
    assert not config.misp_publishing_enabled
