"""CLI-level tests for `hecate-runner promotion-check --json`.

The promotion workflow feeds this output straight into json.loads, so it must
stay a single parseable line regardless of terminal width or bracket content.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from hecate_runner import cli
from hecate_runner.cli import app
from hecate_runner.promotion_policy import PromotionDecision

runner = CliRunner()


def test_json_output_survives_narrow_terminal_and_brackets(monkeypatch: pytest.MonkeyPatch) -> None:
    decision = PromotionDecision(
        hunt_id="H-0001",
        eligible=False,
        review_required=True,
        reasons=[
            "a deliberately long reason that would be wrapped by a narrow eighty column terminal",
            "reason with [red]markup-like[/red] brackets",
        ],
        unsupported_claims=0,
        tlp=None,
        policy_version=1,
    )
    monkeypatch.setattr(cli, "evaluate_promotion", lambda _workspace, _hunt_id, **kwargs: decision)
    monkeypatch.setattr(cli.console, "width", 40)

    result = runner.invoke(app, ["promotion-check", "H-0001", "--json"], env={"COLUMNS": "40"})

    assert result.exit_code == 0, result.output
    assert result.output.count("\n") == 1
    assert json.loads(result.output) == decision.to_dict()
