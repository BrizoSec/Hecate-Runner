"""Tests for Mock BAS Provider."""

from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationStage,
    DetonationTarget,
)
from hecate_runner.bas.mock import MockBASProvider


def test_mock_bas_lookup_technique():
    provider = MockBASProvider()
    assert "ability-powershell-download-cradle" in provider.lookup_technique("T1059.001")
    assert "aws.defense-evasion.cloudtrail-stop" in provider.lookup_technique("T1562.008")
    # Uncataloged fallback
    fallback = provider.lookup_technique("T9999")
    assert len(fallback) == 1
    assert "t9999" in fallback[0]


def test_mock_bas_detonation_success():
    provider = MockBASProvider(allowed_hosts=["lab-01"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging", host="lab-01"),
    )
    result = provider.detonate(request)
    assert result.success is True
    assert result.exit_code == 0
    assert result.stage == DetonationStage.COMPLETED
    assert result.cleanup_success is True
    assert len(result.telemetry_signatures) > 0
    assert result.telemetry_signatures[0]["technique_id"] == "T1059.001"
    assert len(provider.history) == 1


def test_mock_bas_detonation_simulated_failure():
    provider = MockBASProvider(simulate_failure=True)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging"),
    )
    result = provider.detonate(request)
    assert result.success is False
    assert result.exit_code == 1
    assert result.stage == DetonationStage.FAILED
    assert "Simulated adversary detonation error" in result.stderr


def test_mock_bas_cleanup_simulated_failure():
    provider = MockBASProvider(simulate_cleanup_failure=True)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        target=DetonationTarget(environment="staging"),
    )
    result = provider.detonate(request)
    assert result.cleanup_success is False
    assert "Mock cleanup failure" in (result.cleanup_error or "")
    assert provider.cleanup(request) is False


def test_mock_bas_health_check():
    provider = MockBASProvider()
    health = provider.health_check()
    assert health["status"] == "healthy"
    assert health["provider"] == "mock"
    assert health["catalog_techniques"] > 0
