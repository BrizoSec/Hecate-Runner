from pathlib import Path
from unittest.mock import MagicMock, patch

from slack_bolt import App, BoltRequest, BoltResponse

from hecate_runner.config import Settings
from hecate_runner.orchestrator import RunResult
from hecate_runner.slack_blocks import build_runner_status_card, build_slash_help_card
from hecate_runner.slack_bot import SlackBotService


def test_build_slash_help_card():
    card = build_slash_help_card()
    assert len(card) == 1
    blocks = card[0]["blocks"]
    assert any("Hecate SecOps Slash Commands" in b.get("text", {}).get("text", "") for b in blocks)
    section = next(b for b in blocks if b.get("type") == "section")
    text = section["text"]["text"]
    assert "/hecate status" in text
    assert "/hecate hunt" in text
    assert "/hecate deploy" in text
    assert "/hecate rerun" in text


def test_build_runner_status_card(tmp_path: Path):
    workspace = tmp_path / "workspace"
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    (hunts_dir / "H-0500.md").write_text(
        "---\nhunt_id: H-0500\nstatus: active\n---\n", encoding="utf-8"
    )
    (hunts_dir / "H-0501.md").write_text(
        "---\nhunt_id: H-0501\nstatus: planning\n---\n", encoding="utf-8"
    )

    settings = Settings(hecate_workspace=workspace)
    card = build_runner_status_card(settings)
    assert len(card) == 1
    blocks = card[0]["blocks"]
    header = blocks[0]["text"]["text"]
    assert "Hecate Autonomous Runner Status" in header

    fields = blocks[1]["fields"]
    field_texts = " ".join(f["text"] for f in fields)
    assert "2 total" in field_texts
    assert "`1` active" in field_texts
    assert "`1` planning" in field_texts


def _get_command_listener(app: App, command_name: str = "/hecate"):
    req = BoltRequest(body={"command": command_name, "text": "help"}, mode="socket_mode")
    resp = BoltResponse(status=200)
    matched = [listener for listener in app._listeners if listener.matches(req=req, resp=resp)]
    assert len(matched) == 1, f"Expected 1 matcher for command {command_name}"
    return matched[0]


def test_slash_command_help_and_unknown(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True

    cmd_listener = _get_command_listener(mock_app, "/hecate")

    ack_mock = MagicMock()
    respond_mock = MagicMock()

    # 1. /hecate (empty) -> triggers help
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    assert "attachments" in respond_mock.call_args[1]

    # 2. /hecate help
    ack_mock.reset_mock()
    respond_mock.reset_mock()
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "help", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    assert "attachments" in respond_mock.call_args[1]

    # 3. /hecate unknown_subcommand
    ack_mock.reset_mock()
    respond_mock.reset_mock()
    cmd_listener.ack_function(
        ack=ack_mock,
        body={
            "command": "/hecate",
            "text": "unknown_subcommand",
            "user_id": "U123",
            "channel_id": "C123",
        },
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    assert "Unknown command" in respond_mock.call_args[1]["text"]


def test_slash_command_status(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True

    cmd_listener = _get_command_listener(mock_app, "/hecate")

    ack_mock = MagicMock()
    respond_mock = MagicMock()

    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "status", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert ack_mock.called
    assert respond_mock.called
    card = respond_mock.call_args[1]["attachments"]
    assert "Hecate Autonomous Runner Status" in card[0]["blocks"][0]["text"]["text"]


def test_slash_command_deploy(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0505"
    query_dir.mkdir(parents=True)
    (query_dir / "whoami.kql").write_text("DeviceProcessEvents | where FileName == 'whoami.exe'")

    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True

    cmd_listener = _get_command_listener(mock_app, "/hecate")

    ack_mock = MagicMock()
    respond_mock = MagicMock()

    # 1. Missing hunt_id arg
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "deploy", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert "Usage" in respond_mock.call_args[1]["text"]

    # 2. Valid deployment
    ack_mock.reset_mock()
    respond_mock.reset_mock()
    cmd_listener.ack_function(
        ack=ack_mock,
        body={
            "command": "/hecate",
            "text": "deploy H-0505 sentinel_kql",
            "user_id": "U123",
            "channel_id": "C123",
        },
        respond=respond_mock,
    )
    assert ack_mock.called
    text = respond_mock.call_args[1]["text"]
    assert "SIEM & EDR Query Deployment for `H-0505`" in text
    assert "sentinel_kql" in text


def test_slash_command_rerun(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0506"
    query_dir.mkdir(parents=True)
    rule_yaml = """title: Cmd Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
"""
    (query_dir / "rule.yml").write_text(rule_yaml, encoding="utf-8")

    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True

    cmd_listener = _get_command_listener(mock_app, "/hecate")

    ack_mock = MagicMock()
    respond_mock = MagicMock()

    # 1. Missing arg
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "rerun", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert "Usage" in respond_mock.call_args[1]["text"]

    # 2. Valid rerun
    ack_mock.reset_mock()
    respond_mock.reset_mock()
    cmd_listener.ack_function(
        ack=ack_mock,
        body={
            "command": "/hecate",
            "text": "rerun H-0506",
            "user_id": "U123",
            "channel_id": "C123",
        },
        respond=respond_mock,
    )
    assert ack_mock.called
    text = respond_mock.call_args[1]["text"]
    assert "Purple Team Replay for `H-0506` Completed" in text


def test_slash_command_hunt(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True

    cmd_listener = _get_command_listener(mock_app, "/hecate")

    ack_mock = MagicMock()
    respond_mock = MagicMock()

    # 1. Missing topic arg
    cmd_listener.ack_function(
        ack=ack_mock,
        body={"command": "/hecate", "text": "hunt", "user_id": "U123", "channel_id": "C123"},
        respond=respond_mock,
    )
    assert "Usage" in respond_mock.call_args[1]["text"]

    # 2. Trigger ad-hoc hunt with mock
    dummy_result = RunResult(
        outcome="draft_created",
        hunt_id="H-0999",
        draft_path=Path("hunts/2026/Q4/H-0999.md"),
        research_id="R-0999",
    )

    with patch("hecate_runner.slack_bot.execute_adhoc_hunt", return_value=dummy_result):
        ack_mock.reset_mock()
        respond_mock.reset_mock()
        cmd_listener.ack_function(
            ack=ack_mock,
            body={
                "command": "/hecate",
                "text": "hunt Akira Ransomware",
                "user_id": "U123",
                "channel_id": "C123",
            },
            respond=respond_mock,
        )
        assert ack_mock.called
        assert respond_mock.call_count == 2
        # First call is initial acknowledgment
        assert "Ad-hoc Hunt Initiated" in respond_mock.call_args_list[0][1]["text"]
        # Second call is completion result
        assert "Ad-hoc Hunt Completed: `H-0999`" in respond_mock.call_args_list[1][1]["text"]
