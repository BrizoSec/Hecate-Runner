from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from hecate_runner.cli import app
from hecate_runner.config import Settings
from hecate_runner.slack_sim import SlackBotSimulator

runner = CliRunner()

BASE_SIGMA_RULE = """title: Suspicious Process Execution
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""


def _setup_test_workspace(workspace: Path, hunt_id: str = "H-0800") -> None:
    query_dir = workspace / "queries" / hunt_id
    query_dir.mkdir(parents=True, exist_ok=True)
    (query_dir / "rule.yml").write_text(BASE_SIGMA_RULE, encoding="utf-8")
    (query_dir / "rule.kql").write_text(
        'DeviceProcessEvents | where FolderPath endswith "\\\\cmd.exe"', encoding="utf-8"
    )

    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True, exist_ok=True)
    (hunts_dir / f"{hunt_id}.md").write_text(
        f"---\nhunt_id: {hunt_id}\ntitle: Test Hunt\nstatus: planning\n---\n## Grounding\nAudit clean.",
        encoding="utf-8",
    )


def test_simulator_actions(tmp_path: Path):
    workspace = tmp_path / "workspace"
    _setup_test_workspace(workspace, "H-0800")
    settings = Settings(hecate_workspace=workspace)
    sim = SlackBotSimulator(settings=settings)

    # 1. Approve
    with patch("hecate_runner.slack_sim.promote_hunt") as mock_promote:
        mock_promote.return_value = {"ok": True, "path": "hunts/H-0800.md"}
        res = sim.simulate_action("hecate_approve_hunt", "H-0800", user="analyst_bob")
        assert res["ok"] is True
        assert "Approved & Promoted!" in res["message"]
        assert "<@analyst_bob>" in res["message"]

    # 2. Deploy
    res_dep = sim.simulate_action("hecate_deploy_queries", "H-0800", user="analyst_bob")
    assert res_dep["ok"] is True
    assert "Query Deployment for `H-0800`" in res_dep["message"]
    assert len(res_dep["deployments"]) > 0

    # 3. Purple team replay
    with patch("hecate_runner.slack_sim.replay_hunt_purple_team") as mock_replay:
        mock_replay.return_value = {
            "ok": True,
            "total_rules": 1,
            "passed_rules": 1,
            "fidelity": "100.0%",
            "sample_events_count": 20,
        }
        res_rep = sim.simulate_action("hecate_purple_replay", "H-0800")
        assert res_rep["ok"] is True
        assert "Purple Team Replay for `H-0800` Completed" in res_rep["message"]

    # 4. Park
    with patch("hecate_runner.slack_sim.park_hunt") as mock_park:
        mock_park.return_value = {"ok": True}
        res_park = sim.simulate_action("hecate_park_hunt", "H-0800")
        assert res_park["ok"] is True
        assert "Parked / Suppressed" in res_park["message"]

    # 5. Unknown
    res_unk = sim.simulate_action("invalid_action", "H-0800")
    assert res_unk["ok"] is False


def test_simulator_commands(tmp_path: Path):
    workspace = tmp_path / "workspace"
    _setup_test_workspace(workspace, "H-0801")
    settings = Settings(hecate_workspace=workspace)
    sim = SlackBotSimulator(settings=settings)

    # /hecate help
    res_help = sim.simulate_command("/hecate help")
    assert res_help["ok"] is True
    assert "attachments" in res_help

    # /hecate status
    res_status = sim.simulate_command("/hecate status")
    assert res_status["ok"] is True
    assert "attachments" in res_status

    # /hecate deploy H-0801
    res_dep = sim.simulate_command("/hecate deploy H-0801")
    assert res_dep["ok"] is True
    assert "Query Deployment for `H-0801`" in res_dep["text"]

    # /hecate rerun H-0801
    with patch("hecate_runner.slack_sim.replay_hunt_purple_team") as mock_rep:
        mock_rep.return_value = {
            "ok": True,
            "total_rules": 1,
            "passed_rules": 1,
            "fidelity": "100.0%",
            "sample_events_count": 15,
        }
        res_rerun = sim.simulate_command("/hecate rerun H-0801")
        assert res_rerun["ok"] is True
        assert "Purple Team Replay for `H-0801` Completed" in res_rerun["text"]

    # /hecate hunt Akira
    with patch("hecate_runner.slack_sim.execute_adhoc_hunt") as mock_hunt:
        mock_hunt.return_value = MagicMock(
            ok=True,
            hunt_id="H-0802",
            draft_path=Path("hunts/H-0802.md"),
            research_id="res-123",
        )
        res_hunt = sim.simulate_command("/hecate hunt Akira Ransomware")
        assert res_hunt["ok"] is True
        assert "Ad-hoc Hunt Completed: `H-0802`" in res_hunt["text"]


def test_simulator_execute_sim_line_and_tuning(tmp_path: Path):
    workspace = tmp_path / "workspace"
    _setup_test_workspace(workspace, "H-0803")
    settings = Settings(hecate_workspace=workspace)
    sim = SlackBotSimulator(settings=settings)

    # Test conversational rule tuning via line
    out = sim.execute_sim_line("tune H-0803 Exclude svchost.exe")
    assert "Sigma Rule Tuned & Re-Transpiled for `H-0803`" in out
    assert "```diff" in out

    # Test actions via line
    with patch("hecate_runner.slack_sim.promote_hunt") as mock_promote:
        mock_promote.return_value = {"ok": True, "path": "hunts/H-0803.md"}
        out_app = sim.execute_sim_line("approve H-0803")
        assert "Approved & Promoted!" in out_app

    # Test slash command via line
    out_help = sim.execute_sim_line("/hecate help")
    assert "Hecate SecOps Slash Commands" in out_help

    # Test general help
    out_gen_help = sim.execute_sim_line("help")
    assert "Hecate Slack Bot Offline Simulation Harness" in out_gen_help


def test_cli_slack_bot_help():
    import re

    res = runner.invoke(app, ["slack-bot", "--help"])
    assert res.exit_code == 0
    clean_stdout = re.sub(r"\x1b\[[0-9;]*m", "", res.stdout)
    assert "Start the Slack Socket Mode interactive bot daemon" in clean_stdout
    assert "--simulate" in clean_stdout
    assert "--execute-sim" in clean_stdout


def test_cli_slack_bot_execute_sim(tmp_path: Path):
    workspace = tmp_path / "workspace"
    _setup_test_workspace(workspace, "H-0804")

    with patch.dict(
        "os.environ",
        {"HECATE_WORKSPACE": str(workspace)},
        clear=False,
    ):
        res = runner.invoke(app, ["slack-bot", "--execute-sim", "/hecate help"])
        assert res.exit_code == 0
        assert "Hecate SecOps Slash Commands" in res.stdout


def test_cli_slack_bot_missing_tokens(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with patch.dict(
        "os.environ",
        {
            "HECATE_WORKSPACE": str(workspace),
            "SLACK_BOT_TOKEN": "",
            "SLACK_APP_TOKEN": "",
        },
        clear=False,
    ):
        res = runner.invoke(app, ["slack-bot"])
        assert res.exit_code == 1
        assert "Slack Interactive Socket Mode Bot is not fully configured" in res.stdout
        assert "How to set up" in res.stdout


def test_cli_slack_bot_daemon_start(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with (
        patch.dict(
            "os.environ",
            {
                "HECATE_WORKSPACE": str(workspace),
                "SLACK_BOT_TOKEN": "xoxb-test-token",
                "SLACK_APP_TOKEN": "xapp-test-token",
            },
            clear=False,
        ),
        patch("hecate_runner.slack_bot.SlackBotService.start") as mock_start,
    ):
        res = runner.invoke(app, ["slack-bot"])
        assert res.exit_code == 0
        assert mock_start.called
        assert "Starting Hecate Interactive Slack Bot" in res.stdout
