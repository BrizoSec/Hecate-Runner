"""Tests for Stratus Red Team cloud adversary emulation connector."""

import subprocess

import pytest

from hecate_runner.bas.base import (
    DetonationRequest,
    DetonationStage,
    DetonationTarget,
    SafetyViolationError,
)
from hecate_runner.bas.stratus import StratusConnector


def test_stratus_technique_lookup():
    connector = StratusConnector()
    aws_detonators = connector.lookup_technique("T1562.008")
    assert aws_detonators == ["aws.defense-evasion.cloudtrail-stop"]

    azure_detonators = connector.lookup_technique("T1098")
    assert "azure.persistence.add-service-principal-credentials" in azure_detonators

    k8s_detonators = connector.lookup_technique("T1610")
    assert "k8s.privilege-escalation.privileged-pod" in k8s_detonators

    unknown = connector.lookup_technique("T0000")
    assert unknown == []


def test_stratus_health_check_with_runner():
    def mock_runner(args: list[str], timeout: int):
        if args == ["version"]:
            return subprocess.CompletedProcess(
                args=["stratus", "version"],
                returncode=0,
                stdout="stratus-red-team version 2.15.0\n",
                stderr="",
            )
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    connector = StratusConnector(runner_fn=mock_runner)
    health = connector.health_check()
    assert "2.15.0" in health["version"]
    assert health["mapped_techniques"] > 0


def test_stratus_detonation_lifecycle_success():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        return subprocess.CompletedProcess(
            args=["stratus", *args],
            returncode=0,
            stdout=f"stratus {args[0]} executed successfully",
            stderr="",
        )

    connector = StratusConnector(
        runner_fn=mock_runner,
        allowed_accounts=["123456789012"],
    )
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        target=DetonationTarget(
            environment="staging",
            platform="aws",
            cloud_account="123456789012",
        ),
    )

    result = connector.detonate(request)
    assert result.success is True
    assert result.exit_code == 0
    assert result.stage == DetonationStage.COMPLETED
    assert result.ability_id == "aws.defense-evasion.cloudtrail-stop"
    assert result.cleanup_success is True

    # Verify order of execution: warmup -> detonate -> cleanup
    assert len(calls) == 3
    assert calls[0] == ["warmup", "aws.defense-evasion.cloudtrail-stop"]
    assert calls[1] == ["detonate", "aws.defense-evasion.cloudtrail-stop"]
    assert calls[2] == ["cleanup", "aws.defense-evasion.cloudtrail-stop"]

    assert len(result.telemetry_signatures) == 1
    assert result.telemetry_signatures[0]["cloud_provider"] == "aws"


def test_stratus_detonation_warmup_failure_aborts_detonate():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        if args[0] == "warmup":
            return subprocess.CompletedProcess(
                args=["stratus", *args],
                returncode=1,
                stdout="",
                stderr="Terraform init error",
            )
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="", stderr=""
        )

    connector = StratusConnector(runner_fn=mock_runner)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        target=DetonationTarget(environment="staging"),
    )

    result = connector.detonate(request)
    assert result.success is False
    assert result.exit_code == 1
    assert result.stage == DetonationStage.FAILED
    assert "Warmup failed" in result.stderr

    # Detonate was NOT called because warmup failed
    assert len(calls) == 1
    assert calls[0][0] == "warmup"


def test_stratus_detonation_detonate_failure_still_runs_cleanup():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        if args[0] == "detonate":
            return subprocess.CompletedProcess(
                args=["stratus", *args],
                returncode=2,
                stdout="",
                stderr="AWS API rate limit exceeded",
            )
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="", stderr=""
        )

    connector = StratusConnector(runner_fn=mock_runner)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        target=DetonationTarget(environment="staging"),
    )

    result = connector.detonate(request)
    assert result.success is False
    assert result.exit_code == 2

    # Even though detonate failed, cleanup MUST have been invoked
    assert len(calls) == 3
    assert calls[0][0] == "warmup"
    assert calls[1][0] == "detonate"
    assert calls[2][0] == "cleanup"


def test_stratus_detonation_safety_violation():
    connector = StratusConnector(allowed_accounts=["123456789012"])
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        target=DetonationTarget(
            environment="staging",
            cloud_account="999999999999",  # Not on allowlist
        ),
    )
    with pytest.raises(SafetyViolationError):
        connector.detonate(request)


def test_stratus_explicit_cleanup():
    calls: list[list[str]] = []

    def mock_runner(args: list[str], timeout: int):
        calls.append(args)
        return subprocess.CompletedProcess(
            args=["stratus", *args], returncode=0, stdout="cleaned", stderr=""
        )

    connector = StratusConnector(runner_fn=mock_runner)
    request = DetonationRequest(
        hunt_id="H-0885",
        technique_id="T1562.008",
        target=DetonationTarget(environment="staging"),
    )
    assert connector.cleanup(request) is True
    assert calls == [["cleanup", "aws.defense-evasion.cloudtrail-stop"]]
