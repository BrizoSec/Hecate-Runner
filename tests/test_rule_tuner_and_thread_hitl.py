from pathlib import Path
from unittest.mock import MagicMock

from slack_bolt import App, BoltRequest, BoltResponse

from hecate_runner.config import Settings
from hecate_runner.rule_tuner import RuleTuner
from hecate_runner.slack_bot import SlackBotService

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


def test_rule_tuner_infer_field_and_val():
    tuner = RuleTuner(Path("/tmp"))

    # Exclusions
    act, fld, mod, val = tuner._infer_field_and_val("Exclude svchost.exe")
    assert act == "exclude"
    assert fld == "Image"
    assert mod == "endswith"
    assert val == "svchost.exe"

    act, fld, mod, val = tuner._infer_field_and_val("Filter out CommandLine containing /update")
    assert act == "exclude"
    assert fld == "CommandLine"
    assert mod == "contains"
    assert val == "/update"

    act, fld, mod, val = tuner._infer_field_and_val("Exclude User containing SYSTEM")
    assert act == "exclude"
    assert fld == "User"
    assert mod == "contains"
    assert val == "SYSTEM"

    # Inclusions
    act, fld, mod, val = tuner._infer_field_and_val("Broaden Image to include pwsh.exe")
    assert act == "include"
    assert fld == "Image"
    assert mod == "endswith"
    assert val == "pwsh.exe"

    act, fld, mod, val = tuner._infer_field_and_val("Add CommandLine containing whoami")
    assert act == "include"
    assert fld == "CommandLine"
    assert mod == "contains"
    assert val == "whoami"


def test_rule_tuner_yaml_mutation():
    tuner = RuleTuner(Path("/tmp"))

    # Test exclusion
    new_yaml, summary = tuner.tune_rule_yaml(BASE_SIGMA_RULE, "Exclude svchost.exe")
    assert "filter_svchost" in new_yaml
    assert "condition: (selection) and not filter_svchost" in new_yaml
    assert "Added exclusion filter" in summary

    # Test inclusion
    new_yaml2, summary2 = tuner.tune_rule_yaml(BASE_SIGMA_RULE, "Add Image pwsh.exe")
    assert "\\cmd.exe" in new_yaml2
    assert "pwsh.exe" in new_yaml2
    assert "Expanded `Image|endswith` with `pwsh.exe`" in summary2


def test_tune_hunt_rule_end_to_end(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0700"
    query_dir.mkdir(parents=True)
    rule_file = query_dir / "process__execution.yml"
    rule_file.write_text(BASE_SIGMA_RULE, encoding="utf-8")

    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    (hunts_dir / "H-0700.md").write_text(
        "---\nhunt_id: H-0700\ntitle: Test Hunt\nstatus: active\n---\n## Grounding\nAudit clean.",
        encoding="utf-8",
    )

    tuner = RuleTuner(workspace)
    res = tuner.tune_hunt_rule("H-0700", "Exclude svchost.exe")

    assert res.ok is True
    assert res.hunt_id == "H-0700"
    assert "Added exclusion filter" in res.action_summary
    assert "+  filter_svchost:" in res.diff
    assert "-    condition: selection" in res.diff
    assert "+  condition: (selection) and not filter_svchost" in res.diff

    # Verify query files were generated and transpiled
    assert "sentinel_kql" in res.transpiled_targets
    assert "crowdstrike_cql" in res.transpiled_targets
    assert "splunk_spl" in res.transpiled_targets
    assert "elastic_eql" in res.transpiled_targets
    assert "rapid7_leql" in res.transpiled_targets
    assert "sentinelone_s1ql" in res.transpiled_targets

    kql_file = query_dir / "process__execution.kql"
    assert kql_file.exists()
    assert "svchost.exe" in kql_file.read_text(encoding="utf-8")

    spl_file = query_dir / "process__execution.spl"
    assert spl_file.exists()
    assert "svchost.exe" in spl_file.read_text(encoding="utf-8")


def _get_event_listener(app: App, event_type: str = "message"):
    req = BoltRequest(
        body={
            "type": "event_callback",
            "event": {"type": event_type, "thread_ts": "1710000000.000100", "text": "hello"},
        },
        mode="socket_mode",
    )
    resp = BoltResponse(status=200)
    matched = [listener for listener in app._listeners if listener.matches(req=req, resp=resp)]
    assert len(matched) == 1, f"Expected 1 matcher for event {event_type}"
    return matched[0]


def test_slack_thread_message_listener_and_hitl(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0701"
    query_dir.mkdir(parents=True)
    (query_dir / "rule.yml").write_text(BASE_SIGMA_RULE, encoding="utf-8")

    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)

    # 1. Register thread timestamp to H-0701
    thread_ts = "1710000000.000100"
    service.register_thread_hunt(thread_ts, "H-0701")

    msg_listener = _get_event_listener(mock_app, "message")

    say_mock = MagicMock()
    body = {
        "event": {
            "type": "message",
            "thread_ts": thread_ts,
            "text": "Exclude svchost.exe",
            "user": "U12345",
        }
    }

    # Execute thread message handler
    msg_listener.ack_function(body=body, say=say_mock)

    assert say_mock.called
    call_kwargs = say_mock.call_args[1]
    assert call_kwargs["thread_ts"] == thread_ts
    text = call_kwargs["text"]
    assert "Sigma Rule Tuned & Re-Transpiled for `H-0701`" in text
    assert "Added exclusion filter" in text
    assert "```diff" in text


def test_slack_thread_message_explicit_hunt_id_in_text(tmp_path: Path):
    workspace = tmp_path / "workspace"
    query_dir = workspace / "queries" / "H-0702"
    query_dir.mkdir(parents=True)
    (query_dir / "rule.yml").write_text(BASE_SIGMA_RULE, encoding="utf-8")

    settings = Settings(
        hecate_workspace=workspace,
        slack_bot_token="xoxb-fake",
        slack_app_token="xapp-fake",
        slack_interactive_enabled=True,
    )
    mock_app = App(token="xoxb-fake", signing_secret="fake", token_verification_enabled=False)
    service = SlackBotService(settings=settings, app=mock_app)
    assert service.is_configured is True

    msg_listener = _get_event_listener(mock_app, "message")

    say_mock = MagicMock()
    # Unregistered thread_ts, but text mentions H-0702
    body = {
        "event": {
            "type": "message",
            "thread_ts": "1710000099.999999",
            "text": "For H-0702, please exclude svchost.exe",
            "user": "U12345",
        }
    }

    msg_listener.ack_function(body=body, say=say_mock)

    assert say_mock.called
    assert "Sigma Rule Tuned & Re-Transpiled for `H-0702`" in say_mock.call_args[1]["text"]


def test_slack_thread_message_ignored_if_bot_or_non_threaded(tmp_path: Path):
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

    msg_listener = _get_event_listener(mock_app, "message")
    say_mock = MagicMock()

    # Bot message -> ignored
    bot_body = {
        "event": {
            "type": "message",
            "subtype": "bot_message",
            "thread_ts": "1710000000.000100",
            "text": "Exclude svchost.exe",
        }
    }
    msg_listener.ack_function(body=bot_body, say=say_mock)
    assert not say_mock.called

    # Non-threaded message -> ignored
    non_threaded = {
        "event": {
            "type": "message",
            "text": "Exclude svchost.exe",
        }
    }
    msg_listener.ack_function(body=non_threaded, say=say_mock)
    assert not say_mock.called
