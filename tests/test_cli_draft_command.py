"""`hecate-runner draft`: a hunt from intelligence an operator supplies, through the scheduled cycle."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.cli import app
from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.single import SingleItemProvider
from hecate_runner.orchestrator import Orchestrator, RunResult, build_orchestrator_for_item

runner = CliRunner()

INTEL = (
    "Attackers were observed creating scheduled tasks (T1053.005) that launch encoded "
    "PowerShell from a user-writable directory, then beaconing over HTTPS to new domains."
)


@pytest.fixture
def captured(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """The item and settings the command hands to the orchestrator, without running a cycle."""
    seen: dict[str, object] = {}

    def build(settings: Settings, item: CTIItem, ignore_quota: bool = False) -> object:
        seen["item"], seen["settings"], seen["ignore_quota"] = item, settings, ignore_quota

        def run_once(dry_run: bool = False) -> RunResult:
            seen["dry_run"] = dry_run
            return RunResult(
                outcome="draft_created", hunt_id="H-0001", draft_path=Path("/tmp/H-0001.md")
            )

        return type("FakeOrch", (), {"run_once": staticmethod(run_once)})()

    monkeypatch.setattr(cli, "build_orchestrator_for_item", build)
    return seen


def test_the_text_given_becomes_the_item(captured: dict[str, object]) -> None:
    result = runner.invoke(
        app,
        ["draft", INTEL, "--url", "https://report.example/a", "--title", "Scheduled task beacons"],
    )
    assert result.exit_code == 0 and "H-0001" in result.stdout
    item = captured["item"]
    assert isinstance(item, CTIItem)
    assert (item.content, item.source) == (INTEL, "manual")
    assert (item.source_url, item.title) == ("https://report.example/a", "Scheduled task beacons")
    assert captured["dry_run"] is False


def test_a_file_or_standard_input_is_read(captured: dict[str, object], tmp_path: Path) -> None:
    path = tmp_path / "intel.txt"
    path.write_text(f"\n{INTEL}\n")
    assert runner.invoke(app, ["draft", "--file", str(path), "--dry-run"]).exit_code == 0
    item = captured["item"]
    assert isinstance(item, CTIItem) and item.content == INTEL and captured["dry_run"] is True

    assert runner.invoke(app, ["draft"], input=INTEL).exit_code == 0
    item = captured["item"]
    assert isinstance(item, CTIItem) and item.content == INTEL


@pytest.mark.parametrize("args", [["draft", "x", "--file", "/etc/hostname"], ["draft", "   "]])
def test_nothing_to_draft_from_is_refused_before_any_cycle(
    captured: dict[str, object], args: list[str]
) -> None:
    result = runner.invoke(app, args)
    assert result.exit_code == 2 and "item" not in captured


def test_a_supplied_item_goes_through_the_cycle_every_feed_item_does(
    settings: Settings, mock_hecate: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only intake differs: the same Orchestrator, with triage off and nothing read from a feed."""
    monkeypatch.setattr("hecate_runner.orchestrator.HecateClient", lambda **_: mock_hecate)
    feeds = MagicMock()
    monkeypatch.setattr("hecate_runner.orchestrator.get_provider", feeds)
    item = CTIItem(content=INTEL, source="manual", title="Scheduled task beacons")

    orch = build_orchestrator_for_item(settings, item)
    assert type(orch) is Orchestrator and orch.settings.cti_triage == "off"
    result = orch.run_once()

    assert result.outcome == "draft_created" and result.draft_path and result.draft_path.exists()
    feeds.assert_not_called()
    mock_hecate.research_new.assert_called_once()
    mock_hecate.hypothesis_generator.assert_called_once()
    assert mock_hecate.hypothesis_generator.call_args.kwargs["threat_intel"].startswith(INTEL)


def test_the_item_is_offered_until_it_is_acknowledged() -> None:
    item = CTIItem(content=INTEL)
    provider = SingleItemProvider(item)
    assert provider.next_item() is item and provider.next_item() is item
    provider.acknowledge(item)
    assert provider.next_item() is None


def test_force_flag_passes_ignore_quota(captured: dict[str, object]) -> None:
    result = runner.invoke(app, ["draft", INTEL, "--force"])
    assert result.exit_code == 0
    assert captured["ignore_quota"] is True


def test_build_orchestrator_for_item_sets_high_quotas_when_forced(
    settings: Settings, mock_hecate: MagicMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("hecate_runner.orchestrator.HecateClient", lambda **_: mock_hecate)
    item = CTIItem(content=INTEL)
    orch = build_orchestrator_for_item(settings, item, ignore_quota=True)
    assert orch.settings.max_drafts_per_day == 999999
    assert orch.settings.max_research_runs_per_day == 999999
