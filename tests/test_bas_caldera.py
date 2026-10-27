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
):
    abilities = abilities or [
        {
            "ability_id": "psh-cradle-01",
            "name": "PowerShell Download Cradle",
            "technique_id": "T1059.001",
        }
    ]
    poll_states = poll_states or ["finished"]
    poll_call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal poll_call_count
        path = request.url.path

        if path == "/api/v2/health":
            return httpx.Response(200, json={"status": "ok"})

        if path == "/api/v2/agents":
            return httpx.Response(200, json=[{"paw": "agent-01", "group": "staging"}])

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
    connector = CalderaConnector(client=client)
    health = connector.health_check()
    assert health["status"] == "healthy"
    assert health["active_agents"] == 1
    assert "agent-01" in health["staging_agents"]


def test_caldera_lookup_technique():
    client = create_mock_caldera_client()
    connector = CalderaConnector(client=client)
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
    connector = CalderaConnector(client=client)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T9999",
        target=DetonationTarget(environment="staging"),
    )
    result = connector.detonate(request)
    assert result.success is False
    assert result.stage == DetonationStage.FAILED
    assert "No CALDERA ability found" in result.stderr


def test_caldera_detonation_creation_failure():
    client = create_mock_caldera_client(create_status=500)
    connector = CalderaConnector(client=client)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging"),
    )
    result = connector.detonate(request)
    assert result.success is False
    assert result.stage == DetonationStage.FAILED
    assert "Failed to create CALDERA operation: 500" in result.stderr


def test_caldera_detonation_timeout():
    # Never transitions to finished
    client = create_mock_caldera_client(poll_states=["running"])
    connector = CalderaConnector(client=client)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging"),
        timeout_sec=1,  # Short timeout for test
    )
    result = connector.detonate(request)
    assert result.success is False
    assert result.exit_code == 124
    assert result.stage == DetonationStage.FAILED
    assert "timed out" in result.stderr


def test_caldera_detonation_safety_violation():
    client = create_mock_caldera_client()
    connector = CalderaConnector(client=client)
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
    connector = CalderaConnector(client=client, fallback_to_mock=True)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        platform="windows",
        target=DetonationTarget(environment="staging", platform="windows"),
    )
    result = connector.detonate(request)
    assert result.success is True
    assert "Mock Fallback" in result.stdout
    assert len(result.telemetry_signatures) > 0
    assert result.telemetry_signatures[0]["product"] == "windows"
