"""Tests for BAS base data structures and safety enforcement."""

import pytest

from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationResult,
    DetonationStage,
    DetonationTarget,
    SafetyViolationError,
    normalize_platform,
)


@pytest.mark.parametrize(
    "hosts,host", [(None, "lab-01"), ([], "lab-01"), (["*"], "lab-01"), (["lab-01"], None)]
)
def test_live_target_requires_exact_allowlist(hosts, host):
    with pytest.raises(SafetyViolationError):
        DetonationTarget(host=host, environment="lab").validate_safety(allowed_hosts=hosts)


@pytest.mark.parametrize("environment", [" prod ", "production ", "unknown", "", "development"])
def test_environment_is_an_allowlist(environment):
    with pytest.raises(SafetyViolationError):
        DetonationTarget(host="lab-01", environment=environment).validate_safety(
            allowed_hosts=["lab-01"]
        )


def test_unknown_platform_does_not_default_to_linux():
    with pytest.raises(ValueError):
        normalize_platform("linxu")


def test_detonation_target_safety_rejects_production():
    """Safety guardrail must refuse detonation in production environments."""
    target = DetonationTarget(environment="production", host="srv-01")
    with pytest.raises(SafetyViolationError, match="flagged as 'production'"):
        target.validate_safety()

    target_prod = DetonationTarget(environment="PROD", host="srv-01")
    with pytest.raises(SafetyViolationError, match="flagged as 'PROD'"):
        target_prod.validate_safety()


def test_detonation_target_safety_allows_staging_and_lab():
    """Staging and lab environments pass validation when on allowlist."""
    target = DetonationTarget(environment="staging", host="lab-host-01")
    target.validate_safety(allowed_hosts=["lab-host-01", "lab-host-02"])

    target_wildcard = DetonationTarget(environment="lab", host="any-host")
    with pytest.raises(SafetyViolationError):
        target_wildcard.validate_safety(allowed_hosts=["*"])


def test_detonation_target_safety_rejects_unlisted_host():
    """Host not present in allowed_hosts is blocked."""
    target = DetonationTarget(environment="staging", host="unlisted-server")
    with pytest.raises(SafetyViolationError, match="explicit target"):
        target.validate_safety(allowed_hosts=["lab-host-01"])


def test_detonation_target_safety_rejects_unlisted_cloud_account():
    """Cloud account not present in allowed_accounts is blocked."""
    target = DetonationTarget(
        environment="staging",
        platform="aws",
        cloud_account="999888777666",
    )
    with pytest.raises(SafetyViolationError, match="explicit target"):
        target.validate_safety(allowed_accounts=["111222333444"])


def test_detonation_target_safety_allows_whitelisted_cloud_account():
    """Whitelisted cloud account passes safety check."""
    target = DetonationTarget(
        environment="staging",
        platform="aws",
        cloud_account="111222333444",
    )
    target.validate_safety(allowed_accounts=["111222333444"])


def test_detonation_request_serialization_round_trip():
    """DetonationRequest to_dict and from_dict preserves all fields."""
    req = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1059.001",
        ability_id="caldera-psh-01",
        platform="windows",
        target=DetonationTarget(environment="staging", host="win-lab-01"),
        timeout_sec=90,
        cleanup_on_finish=True,
        params={"var": "val"},
    )
    d = req.to_dict()
    assert d["hunt_id"] == "H-0885"
    assert d["target"]["host"] == "win-lab-01"

    restored = DetonationRequest.from_dict(d)
    assert restored.hunt_id == req.hunt_id
    assert restored.target.host == "win-lab-01"
    assert restored.target.environment == "staging"


def test_detonation_result_summary_formatting():
    """DetonationResult summary formats success and failure clearly."""
    res_success = DetonationResult(
        success=True,
        hunt_id="H-0885",
        technique_id="T1059.001",
        ability_id="ability-123",
        provider="caldera",
        start_time_utc="2026-10-27T00:00:00Z",
        end_time_utc="2026-10-27T00:00:10Z",
        duration_seconds=10.0,
        exit_code=0,
        stdout="executed",
        stderr="",
        stage=DetonationStage.COMPLETED,
        cleanup_success=True,
    )
    summary = res_success.summary()
    assert "[✓] CALDERA: T1059.001 (ability-123)" in summary
    assert "Exit: 0 (10.00s)" in summary

    d = res_success.to_dict()
    assert d["stage"] == "completed"
    restored = DetonationResult.from_dict(d)
    assert restored.stage == DetonationStage.COMPLETED
    assert restored.success is True
