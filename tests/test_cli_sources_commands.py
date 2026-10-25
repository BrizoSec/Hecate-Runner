from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app

runner = CliRunner()


@pytest.fixture
def cli_env(workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # chdir is not optional here, for two reasons, and this fixture was
    # missing it. `sources enable/disable` writes `.env` relative to the cwd,
    # so without this the tests below edited and deleted the developer's real
    # Hecate-Runner/.env -- API keys and all -- on every run. Settings() also
    # resolves a relative env_file=".env" from the cwd, so the real file would
    # otherwise leak OTX_API_KEY/MISP_API_KEY into these tests and defeat the
    # delenv below. Same reasoning as the fixture in
    # tests/test_cli_status_commands.py.
    monkeypatch.chdir(tmp_path)
    for var in [
        "HECATE_WORKSPACE",
        "HECATE_RUNNER_CTI_PROVIDER",
        "HECATE_RUNNER_CTI_MULTI_PROVIDERS",
        "OTX_API_KEY",
        "MISP_BASE_URL",
        "MISP_API_KEY",
    ]:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_RSS_FEED_URLS", "https://example.com/feed")
    monkeypatch.setenv("TAVILY_API_KEY", "test-tavily-key")
    (workspace / ".env").touch()
    return workspace


class TestSourcesCommands:
    def test_list_sources(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["sources", "list"])
        assert result.exit_code == 0
        assert "CTI Sources Configuration" in result.stdout
        assert "otx" in result.stdout
        assert "misp" in result.stdout
        assert "dfir_report" in result.stdout
        assert "vulncheck" in result.stdout
        assert "censys_c2" in result.stdout
        assert "shadowserver" in result.stdout
        assert "msrc" in result.stdout
        assert "cloud_threat" in result.stdout

    def test_enable_source(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # Currently defaults to file in tests? Wait, cli_env doesn't set provider, default is file.
        # But wait, we should test enabling.
        result = runner.invoke(app, ["sources", "enable", "otx"])
        assert result.exit_code == 0
        assert "Enabled otx" in result.stdout

    def test_disable_source(self, cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HECATE_RUNNER_CTI_PROVIDER", "multi")
        monkeypatch.setenv("HECATE_RUNNER_CTI_MULTI_PROVIDERS", "otx,rss")

        result = runner.invoke(app, ["sources", "disable", "otx"])
        assert result.exit_code == 0
        assert "Disabled otx" in result.stdout

    def test_reset_cursor(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["sources", "reset", "invalid_source"])
        assert result.exit_code == 1
        assert "Unknown source" in result.stdout
