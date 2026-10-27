"""Tests for MITRE CALDERA connector."""

import httpx
import pytest

from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationStage,
    DetonationTarget,
    SafetyViolationError,
)
from hecate_runner.bas.caldera import CalderaConnector


def create_mock_caldera_client(
    abilities=None,
    create_status=200,
    poll_states=None,
    link_results=None,
    agents=None,
    calls=None,
):
    if abilities is None:
        abilities = [
            {
                "ability_id": "psh-cradle-01",
                "technique_id": "T1059.001",
                "executors": [{"platform": "linux"}],
            }
        ]
    poll_states = poll_states or ["finished"]
    poll_call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal poll_call_count
        if calls is not None:
            calls.append(request)
        path = request.url.path

        if path == "/api/v2/health":
            return httpx.Response(200, json={"status": "ok"})

        if path == "/api/v2/agents":
            return httpx.Response(
                200,
                json=agents
                if agents is not None
                else [
                    {
                        "paw": "agent-01",
                        "host": "agent-01",
                        "platform": "linux",
                        "trusted": True,
                        "group": "staging",
                    }
                ],
            )

        if path == "/api/v2/abilities":
            return httpx.Response(200, json=abilities)

        if path == "/api/v2/operations" and request.method == "POST":
            if create_status != 200:
                return httpx.Response(create_status, text="Server Error")
            return httpx.Response(200, json={"id": "op-123", "name": "hecate_test_op"})

        if path.startswith("/api/v2/operations/op-123/links/"):
            return httpx.Response(200, json={"result": "payload executed"})

        if path == "/api/v2/operations/op-123":
            idx = min(poll_call_count, len(poll_states) - 1)
            state = poll_states[idx]
            poll_call_count += 1
            return httpx.Response(
                200,
                json={
                    "id": "op-123",
                    "state": state,
                    "chain": [
                        {
                            "id": "link-1",
                            "paw": "agent-01",
                            "status": 0 if state == "finished" else -3,
                            "command": "powershell.exe -enc ...",
                            "collect": "2026-10-27T00:00:00Z",
                            "finish": "2026-10-27T00:00:05Z" if state == "finished" else None,
                        }
                    ],
                },
            )

        return httpx.Response(404, json={"error": "not found"})

    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport, base_url="http://caldera.test")


def test_caldera_health_check():
    client = create_mock_caldera_client()
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    health = connector.health_check()
    assert health["status"] == "healthy"
    assert health["active_agents"] == 1
    assert "agent-01" in health["staging_agents"]


def test_caldera_lookup_technique():
    client = create_mock_caldera_client()
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    abilities = connector.lookup_technique("T1059.001")
    assert abilities == ["psh-cradle-01"]

    unknown = connector.lookup_technique("T9999")
    assert unknown == []


def test_caldera_detonation_success():
    client = create_mock_caldera_client(poll_states=["running", "finished"])
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging", host="agent-01"),
        timeout_sec=5,
    )

    result = connector.detonate(request)
    assert result.success is True
    assert result.exit_code == 0
    assert result.stage == DetonationStage.COMPLETED
    assert result.ability_id == "psh-cradle-01"
    assert "payload executed" in result.stdout
    assert len(result.telemetry_signatures) == 1
    assert result.telemetry_signatures[0]["paw"] == "agent-01"


def test_caldera_detonation_unknown_technique():
    client = create_mock_caldera_client(abilities=[])
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T9999",
        target=DetonationTarget(environment="staging", host="agent-01"),
    )
    result = connector.detonate(request)
    assert result.success is False
    assert result.stage == DetonationStage.FAILED
    assert "No CALDERA ability found" in result.stderr


def test_caldera_detonation_creation_failure():
    client = create_mock_caldera_client(create_status=500)
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging", host="agent-01"),
    )
    result = connector.detonate(request)
    assert result.success is False
    assert result.stage == DetonationStage.FAILED
    assert "Failed to create CALDERA operation: 500" in result.stderr


def test_caldera_detonation_timeout():
    # Never transitions to finished
    client = create_mock_caldera_client(poll_states=["running"])
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging", host="agent-01"),
        timeout_sec=1,  # Short timeout for test
    )
    result = connector.detonate(request)
    assert result.success is False
    assert result.exit_code == 124
    assert result.stage == DetonationStage.FAILED
    assert "timed out" in result.stderr


def test_caldera_detonation_safety_violation():
    client = create_mock_caldera_client()
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="production"),
    )
    with pytest.raises(SafetyViolationError):
        connector.detonate(request)


def test_caldera_detonation_fallback_to_mock():
    # Only linux agent exists in mock client, request is windows
    client = create_mock_caldera_client()
    connector = CalderaConnector(client=client, allowed_hosts=["agent-01"], fallback_to_mock=True)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        platform="windows",
        target=DetonationTarget(environment="staging", platform="windows", host="agent-01"),
    )
    result = connector.detonate(request)
    assert result.success is True
    assert result.provider == "mock"
    assert result.raw_details["mock_fallback"] is True
    assert "Mock Fallback" in result.stdout
    assert len(result.telemetry_signatures) > 0
    assert result.telemetry_signatures[0]["product"] == "windows"


@pytest.mark.parametrize(
    "agents",
    [
        [],
        [
            {
                "host": "other-host",
                "paw": "agent-01",
                "group": "staging",
                "platform": "linux",
                "trusted": True,
            }
        ],
        [
            {
                "host": "agent-01",
                "paw": "agent-01",
                "group": "staging",
                "platform": "linux",
                "trusted": False,
            }
        ],
        [
            {
                "host": "agent-01",
                "paw": "agent-01",
                "group": "staging",
                "platform": "windows",
                "trusted": True,
            }
        ],
        [
            {
                "host": "agent-01",
                "paw": str(i),
                "group": "staging",
                "platform": "linux",
                "trusted": True,
            }
            for i in range(2)
        ],
    ],
)
def test_target_preflight_blocks_before_any_mutation(agents):
    calls = []
    connector = CalderaConnector(
        client=create_mock_caldera_client(agents=agents, calls=calls), allowed_hosts=["agent-01"]
    )
    with pytest.raises(SafetyViolationError):
        connector.detonate(
            DetonationRequest(
                hunt_id="H-TEST",
                technique_id="T1033",
                target=DetonationTarget(host="agent-01", environment="lab"),
            )
        )
    assert all(call.method == "GET" for call in calls)


def test_timeout_stops_remote_operation_and_does_not_claim_cleanup():
    import json

    calls = []
    connector = CalderaConnector(
        client=create_mock_caldera_client(poll_states=["running"], calls=calls),
        allowed_hosts=["agent-01"],
    )
    result = connector.detonate(
        DetonationRequest(
            hunt_id="H-TEST",
            technique_id="T1059.001",
            timeout_sec=1,
            target=DetonationTarget(host="agent-01", environment="lab"),
        )
    )
    assert not result.success
    assert not result.cleanup_success
    assert any(
        call.method == "POST"
        and call.url.path == "/api/rest"
        and json.loads(call.content).get("state") == "finished"
        for call in calls
    )
