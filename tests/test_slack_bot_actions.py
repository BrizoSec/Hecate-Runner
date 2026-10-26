from pathlib import Path
from unittest.mock import MagicMock

from hecate_runner.config import Settings
from hecate_runner.orchestrator import RunResult
from hecate_runner.slack_blocks import build_draft_card, build_hunt_completed_card
from hecate_runner.slack_bot import (
    SlackBotService,
    deploy_queries_for_hunt,
    park_hunt,
    promote_hunt,
    replay_hunt_purple_team,
)


def _make_dummy_run_result(hunt_id: str = "H-0899") -> RunResult:
    return RunResult(
        outcome="draft_created",
        hunt_id=hunt_id,
        draft_path=Path(f"hunts/2026/Q4/{hunt_id}.md"),
        research_id="R-0123",
        parked_count=1,
    )


def test_build_draft_card_interactive_buttons():
    result = _make_dummy_run_result("H-0899")

    # Non-interactive
    plain_card = build_draft_card(result, interactive=False)
    plain_actions = [b for b in plain_card[0]["blocks"] if b.get("type") == "actions"]
    assert len(plain_actions) == 0

    # Interactive
    interactive_card = build_draft_card(result, interactive=True)
    actions_blocks = [b for b in interactive_card[0]["blocks"] if b.get("type") == "actions"]
    assert len(actions_blocks) == 1

    action_ids = [el.get("action_id") for el in actions_blocks[0]["elements"]]
    assert "hecate_approve_hunt" in action_ids
    assert "hecate_deploy_queries" in action_ids
    assert "hecate_rerun_purple" in action_ids
    assert "hecate_park_hunt" in action_ids

    # Values must match hunt_id
    for el in actions_blocks[0]["elements"]:
        assert el.get("value") == "H-0899"


def test_build_hunt_completed_card_interactive_buttons():
    # Non-interactive
    plain = build_hunt_completed_card(
        hunt_id="H-0899",
        topic="Akira Ransomware",
        techniques=["T1059.001", "T1078"],
        sigma_count=2,
        interactive=False,
    )
    plain_actions = [
        b
        for b in plain[0]["blocks"]
        if b.get("type") == "actions" and b.get("block_id", "").startswith("hunt_actions_")
    ]
    assert len(plain_actions) == 0

    # Interactive
    interactive = build_hunt_completed_card(
        hunt_id="H-0899",
        topic="Akira Ransomware",
        techniques=["T1059.001", "T1078"],
        sigma_count=2,
        interactive=True,
    )
    interactive_actions = [
        b
        for b in interactive[0]["blocks"]
        if b.get("type") == "actions" and b.get("block_id") == "hunt_actions_H-0899"
    ]
    assert len(interactive_actions) == 1
    action_ids = [el.get("action_id") for el in interactive_actions[0]["elements"]]
    assert "hecate_approve_hunt" in action_ids
    assert "hecate_deploy_queries" in action_ids
    assert "hecate_rerun_purple" in action_ids
    assert "hecate_park_hunt" in action_ids


def test_promote_hunt(tmp_path: Path):
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0100.md"
    hunt_file.write_text(
        "---\nhunt_id: H-0100\ntitle: Akira Lateral Movement\nstatus: planning\n---\n\n## Summary\nTest content",
        encoding="utf-8",
    )

    res = promote_hunt(workspace, "H-0100")
    assert res["ok"] is True
    assert res["status"] == "active"
    assert res["already_promoted"] is False
    assert "status: active" in hunt_file.read_text(encoding="utf-8")

    # Second invocation recognizes already active
    res2 = promote_hunt(workspace, "H-0100")
    assert res2["ok"] is True
    assert res2["already_promoted"] is True


def test_park_hunt(tmp_path: Path):
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0101.md"
    hunt_file.write_text(
        "---\nhunt_id: H-0101\ntitle: Noise Campaign\nstatus: planning\n---\n\n## Content",
        encoding="utf-8",
    )

    res = park_hunt(workspace, "H-0101", reason="False positive flood")
    assert res["ok"] is True
    assert res["status"] == "suppressed"
    assert "status: suppressed" in hunt_file.read_text(encoding="utf-8")


def test_deploy_queries_for_hunt(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0102"
    query_dir.mkdir(parents=True)

    (query_dir / "proc__test.kql").write_text(
        "DeviceProcessEvents | where FileName == 'cmd.exe'", encoding="utf-8"
    )
    (query_dir / "proc__test.spl").write_text('Image="*\\cmd.exe"', encoding="utf-8")

    results = deploy_queries_for_hunt(workspace, "H-0102", dry_run=True)
    assert len(results) == 2
    targets = {r["target"] for r in results}
    assert targets == {"sentinel_kql", "splunk_spl"}
    for r in results:
        assert r["ok"] is True
        assert r["status"] == "dry_run"
        assert r["remote_id"] is not None


def test_replay_hunt_purple_team(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0103"
    query_dir.mkdir(parents=True)

    rule_yaml = """title: Suspicious Cmdline
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell.exe -enc'
    condition: selection
"""
    (query_dir / "rule.yml").write_text(rule_yaml, encoding="utf-8")

    res = replay_hunt_purple_team(workspace, "H-0103")
    assert res["ok"] is True
    assert res["total_rules"] == 1
    assert "sample_events_count" in res


def test_slack_bot_action_handlers_execution(tmp_path: Path):
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    hunt_file = hunts_dir / "H-0104.md"
    hunt_file.write_text(
        "---\nhunt_id: H-0104\ntitle: Action Handler Test\nstatus: planning\n---\n",
        encoding="utf-8",
    )

    query_dir = workspace / "queries" / "H-0104"
    query_dir.mkdir(parents=True)
    (query_dir / "test.kql").write_text(
        "DeviceProcessEvents | where FileName == 'whoami.exe'", encoding="utf-8"
    )

    from slack_bolt import App

    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True
    assert len(mock_app._listeners) >= 4

    from slack_bolt import BoltRequest, BoltResponse

    def _get_listener(action_id: str):
        req = BoltRequest(
            body={
                "type": "block_actions",
                "actions": [{"action_id": action_id, "value": "H-0104"}],
            },
            mode="socket_mode",
        )
        resp = BoltResponse(status=200)
        matched = [
            listener for listener in mock_app._listeners if listener.matches(req=req, resp=resp)
        ]
        assert len(matched) == 1, f"Expected 1 matcher for {action_id}"
        return matched[0]

    ack_mock = MagicMock()
    say_mock = MagicMock()
    body = {
        "type": "block_actions",
        "actions": [{"value": "H-0104"}],
        "user": {"id": "U12345", "name": "alice"},
        "message": {"ts": "1710000000.000100"},
        "channel": {"id": "C12345"},
    }

    # 1. Test approve handler
    l_approve = _get_listener("hecate_approve_hunt")
    l_approve.ack_function(ack=ack_mock, body=body, say=say_mock)
    assert ack_mock.called
    assert say_mock.called
    assert "status: active" in hunt_file.read_text(encoding="utf-8")

    # 2. Test deploy queries handler
    ack_mock.reset_mock()
    say_mock.reset_mock()
    l_deploy = _get_listener("hecate_deploy_queries")
    l_deploy.ack_function(ack=ack_mock, body=body, say=say_mock)
    assert ack_mock.called
    assert say_mock.called
    assert "SIEM & EDR Query Deployment" in say_mock.call_args[1]["text"]

    # 3. Test purple team replay handler
    ack_mock.reset_mock()
    say_mock.reset_mock()
    l_purple = _get_listener("hecate_rerun_purple")
    l_purple.ack_function(ack=ack_mock, body=body, say=say_mock)
    assert ack_mock.called
    assert say_mock.called
    assert "Purple Team Replay" in say_mock.call_args[1]["text"]

    # 4. Test park handler
    ack_mock.reset_mock()
    say_mock.reset_mock()
    l_park = _get_listener("hecate_park_hunt")
    l_park.ack_function(ack=ack_mock, body=body, say=say_mock)
    assert ack_mock.called
    assert say_mock.called
    assert "status: suppressed" in hunt_file.read_text(encoding="utf-8")


def test_slack_bot_unconfigured_safety():
    settings = Settings(
        slack_bot_token=None,
        slack_app_token=None,
        slack_interactive_enabled=False,
    )
    service = SlackBotService(settings=settings)
    assert service.is_configured is False
    assert service.app is None
    # Calling start should log warning and return cleanly without crashing
    service.start()
    service.close()
