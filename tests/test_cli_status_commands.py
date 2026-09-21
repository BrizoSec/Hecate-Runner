"""CLI-level tests for `status`, `config`, and `doctor`.

Uses typer's CliRunner against the real `app`, setting env vars via
monkeypatch since each command constructs its own Settings() from the
process environment. Mirrors the pattern in test_cli_query_commands.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app

runner = CliRunner()


@pytest.fixture
def cli_env(workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # doctor()/status()/config() construct Settings() fresh with no
    # _env_file override (unlike the `settings` fixture), so pydantic-
    # settings' relative env_file=".env" lookup would otherwise pick up the
    # *real* Hecate-Runner/.env in the repo root (pytest's cwd) -- leaking
    # real OTX_API_KEY/MISP_API_KEY/etc. into these tests and defeating the
    # delenv below. chdir somewhere with no .env at all. Deliberately not
    # `workspace` itself: one test below writes workspace/.env on purpose,
    # a *different*, intentional lookup path (_env_key_available checks
    # settings.hecate_workspace / ".env" explicitly).
    monkeypatch.chdir(tmp_path)
    for var in [
        "HECATE_WORKSPACE",
        "HECATE_RUNNER_MAX_DRAFTS_PER_DAY",
        "HECATE_RUNNER_CTI_PROVIDER",
        "HECATE_RUNNER_CTI_MULTI_PROVIDERS",
        "OTX_API_KEY",
        "MISP_BASE_URL",
        "MISP_API_KEY",
        "TAVILY_API_KEY",
        "HECATE_RUNNER_RESEARCH_ENABLED",
        "HECATE_RUNNER_SLACK_WEBHOOK_URL",
        "HECATE_RUNNER_QUERY_PROVIDER",
        "SPLUNK_HOST",
        "SPLUNK_TOKEN",
    ]:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "4")
    # doctor's RSS check is unconditional; keep it satisfied unless a test
    # explicitly needs it empty.
    monkeypatch.setenv("HECATE_RUNNER_RSS_FEED_URLS", "https://example.com/feed")
    # Research grounding is a hard check when research is enabled, so the
    # healthy baseline has to carry a key. Tests that care about its absence
    # delete it themselves.
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily-key")

    # Mock environment checks so tests pass regardless of CI runner state
    monkeypatch.setattr("hecate_runner.cli._module_available", lambda _: True)
    monkeypatch.setattr("hecate_runner.cli._stix_data_available", lambda: True)

    return workspace


class TestStatusCommand:
    def test_prints_table_with_defaults(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "hecate-runner status" in result.stdout
        assert "Drafts today" in result.stdout
        assert "0 / 4" in result.stdout
        assert "(never)" in result.stdout


class TestConfigCommand:
    def test_dumps_valid_json_with_derived_paths(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["config"])

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "_derived" in data
        assert "hunts_root" in data["_derived"]
        assert "log_file" in data["_derived"]

    def test_secrets_are_redacted(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OTX_API_KEY", "super-secret-value")

        result = runner.invoke(app, ["config"])

        assert "super-secret-value" not in result.stdout


class TestDoctorCommand:
    def test_all_checks_pass_with_healthy_file_provider(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "file")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 0
        assert "All checks passed" in result.stdout

    def test_missing_workspace_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path / "does-not-exist"))
        monkeypatch.setenv("HECATE_RUNNER_RSS_FEED_URLS", "https://example.com/feed")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "problem(s) found" in result.stdout

    def test_otx_provider_without_key_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "otx")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "OTX_API_KEY" in result.stdout

    def test_otx_provider_with_key_passes_that_check(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "otx")
        monkeypatch.setenv("OTX_API_KEY", "test-key")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 0

    def test_misp_provider_without_creds_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "misp")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "MISP_BASE_URL" in result.stdout

    def test_multi_provider_with_invalid_list_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "multi")
        monkeypatch.setenv("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1

    def test_multi_provider_valid_list_checks_each_sub_provider(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "multi")
        monkeypatch.setenv("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "otx,rss")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1  # otx sub-provider still missing its key
        assert "OTX_API_KEY" in result.stdout

    def test_missing_rss_feeds_fails(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
        monkeypatch.setenv("HECATE_RUNNER_RSS_FEED_URLS", "")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "RSS feed URLs" in result.stdout

    def test_research_enabled_without_tavily_key_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Promoted from a warning deliberately.

        doctor already labelled grounding "mandatory-when-enabled" while
        letting it pass, so a deployment could report healthy while every
        research run went ungrounded. Turning research off is the supported
        way to run without a key.
        """
        monkeypatch.setenv("HECATE_RUNNER_RESEARCH_ENABLED", "true")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "TAVILY_API_KEY" in result.stdout

    def test_research_disabled_without_tavily_key_passes(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_RESEARCH_ENABLED", "false")
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 0
        assert "All checks passed" in result.stdout

    def test_missing_agent_capability_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The runner drives hecate_agent in-process, so a capability missing
        from *this* environment silently disables it. doctor reported healthy
        through exactly that, which is why these are hard checks."""
        import hecate_runner.cli as cli_mod

        real = cli_mod._module_available
        monkeypatch.setattr(
            cli_mod,
            "_module_available",
            lambda name: False if name == "sklearn" else real(name),
        )

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "scikit-learn importable" in result.stdout

    def test_stix_package_without_data_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The package alone is not enough. Without the downloaded bundle every
        technique ID resolves to nothing and drafts ship with empty
        `techniques:` frontmatter, so this is checked separately."""
        import hecate_runner.cli as cli_mod

        monkeypatch.setattr(cli_mod, "_stix_data_available", lambda: False)

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "ATT&CK STIX data present" in result.stdout
        assert "attack update" in result.stdout

    def test_slack_webhook_absent_warns_not_fails(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 0
        assert "SLACK_WEBHOOK_URL" in result.stdout

    def test_mock_query_provider_shows_info_note(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["doctor"])

        assert "cannot touch a real" in result.stdout

    def test_splunk_query_provider_without_creds_fails(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "splunk")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 1
        assert "SPLUNK_HOST" in result.stdout

    def test_splunk_query_provider_with_creds_in_workspace_env_passes(
        self, cli_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HECATE_RUNNER_QUERY_PROVIDER", "splunk")
        (cli_env / ".env").write_text("SPLUNK_HOST=splunk.example.com\nSPLUNK_TOKEN=abc123\n")

        result = runner.invoke(app, ["doctor"])

        assert result.exit_code == 0
