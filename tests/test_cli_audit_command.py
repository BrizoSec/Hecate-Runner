"""CLI-level tests for `hecate-runner audit`.

Mirrors the CliRunner pattern in test_cli_run_and_poll_commands.py, against a
temporary workspace holding real-shaped hunt files.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import app

runner = CliRunner()

_CLEAN_HUNT = """---
hunt_id: H-0100
spawned_from: R-0100
---

### Threat Context

Source CTI:

> MISP Event: The Chrysalis Backdoor
MITRE ATT&CK Techniques: T1071.001

### Justification

The Chrysalis backdoor beacons to C2.

### Grounding

placeholder

### Related Tickets
"""

_FABRICATING_HUNT = _CLEAN_HUNT.replace("H-0100", "H-0101").replace(
    "The Chrysalis backdoor beacons to C2.",
    "Initial access via CVE-2024-1234, attributed to APT41.",
)


@pytest.fixture
def workspace_with_hunts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    quarter = tmp_path / "hunts" / "2026" / "Q3"
    quarter.mkdir(parents=True)
    (quarter / "H-0100.md").write_text(_CLEAN_HUNT)
    (quarter / "H-0101.md").write_text(_FABRICATING_HUNT)
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    return tmp_path


def test_audits_every_hunt_by_default(workspace_with_hunts: Path) -> None:
    result = runner.invoke(app, ["audit"])
    assert result.exit_code == 0
    assert "H-0100" in result.stdout
    assert "H-0101" in result.stdout


def test_reports_the_fabricated_claims_by_name(workspace_with_hunts: Path) -> None:
    result = runner.invoke(app, ["audit"])
    assert "CVE-2024-1234" in result.stdout
    assert "APT41" in result.stdout


def test_a_single_hunt_can_be_named(workspace_with_hunts: Path) -> None:
    result = runner.invoke(app, ["audit", "H-0100"])
    assert result.exit_code == 0
    assert "H-0101" not in result.stdout


def test_an_unknown_hunt_id_exits_non_zero(workspace_with_hunts: Path) -> None:
    """Silently reporting nothing would read as "audited, all clean"."""
    result = runner.invoke(app, ["audit", "H-9999"])
    assert result.exit_code == 1
    assert "No file found for H-9999" in result.stdout


def test_strict_exits_non_zero_when_a_claim_traces_to_no_source(
    workspace_with_hunts: Path,
) -> None:
    assert runner.invoke(app, ["audit", "--strict"]).exit_code == 1


def test_strict_exits_zero_when_every_claim_is_grounded(workspace_with_hunts: Path) -> None:
    assert runner.invoke(app, ["audit", "H-0100", "--strict"]).exit_code == 0


def test_update_rewrites_the_grounding_section(workspace_with_hunts: Path) -> None:
    """The point of the command: a hunt graded by an older audit gets the
    current verdict without being redrafted."""
    hunt = workspace_with_hunts / "hunts" / "2026" / "Q3" / "H-0101.md"
    assert "placeholder" in hunt.read_text()

    assert runner.invoke(app, ["audit", "--update"]).exit_code == 0

    refreshed = hunt.read_text()
    assert "placeholder" not in refreshed
    assert "CVE-2024-1234" in refreshed
    assert "UNSUPPORTED" in refreshed
    # Surrounding structure survives the surgery.
    assert refreshed.startswith("---\nhunt_id: H-0101")
    assert "### Related Tickets" in refreshed


def test_update_is_idempotent(workspace_with_hunts: Path) -> None:
    hunt = workspace_with_hunts / "hunts" / "2026" / "Q3" / "H-0100.md"
    runner.invoke(app, ["audit", "--update"])
    once = hunt.read_text()
    runner.invoke(app, ["audit", "--update"])
    assert hunt.read_text() == once


def test_without_update_the_files_are_untouched(workspace_with_hunts: Path) -> None:
    hunt = workspace_with_hunts / "hunts" / "2026" / "Q3" / "H-0101.md"
    before = hunt.read_text()
    runner.invoke(app, ["audit"])
    assert hunt.read_text() == before


def test_an_empty_workspace_is_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "hunts").mkdir()
    (tmp_path / "logs").mkdir()
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path))
    result = runner.invoke(app, ["audit"])
    assert result.exit_code == 0
    assert "No hunt files matched" in result.stdout
