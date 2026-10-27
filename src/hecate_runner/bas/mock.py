"""Mock BAS Provider for testing, local development, and offline CI/CD."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from hecate_runner.bas.base import (
    BASProvider,
    DetonationRequest,
    DetonationResult,
    DetonationStage,
)

log = logging.getLogger(__name__)

# Sample deterministic techniques supported by the mock provider
MOCK_TECHNIQUE_CATALOG: dict[str, list[str]] = {
    "T1059.001": ["ability-powershell-download-cradle", "ability-powershell-base64-exec"],
    "T1059.003": ["ability-cmd-obfuscated-echo", "ability-cmd-whoami-recon"],
    "T1003.001": ["ability-lsass-comsvcs-minidump"],
    "T1562.008": ["aws.defense-evasion.cloudtrail-stop"],
    "T1098.001": ["aws.persistence.create-admin-access-key"],
    "T1530": ["aws.exfiltration.s3-bucket-dump"],
    "T1610": ["k8s.privilege-escalation.privileged-pod"],
}


class MockBASProvider(BASProvider):
    """Deterministic in-memory BAS provider."""

    name: str = "mock"
    provider_type: str = "simulator"

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
        simulate_failure: bool = False,
        simulate_cleanup_failure: bool = False,
        artificial_delay_sec: float = 0.0,
    ):
        super().__init__(allowed_hosts=allowed_hosts, allowed_accounts=allowed_accounts)
        self.simulate_failure = simulate_failure
        self.simulate_cleanup_failure = simulate_cleanup_failure
        self.artificial_delay_sec = artificial_delay_sec
        self.history: list[DetonationRequest] = []
        self.cleanup_calls: list[DetonationRequest] = []

    def lookup_technique(self, technique_id: str) -> list[str]:
        return MOCK_TECHNIQUE_CATALOG.get(technique_id, [f"mock-ability-{technique_id.lower()}"])

    def detonate(self, request: DetonationRequest) -> DetonationResult:
        # Enforce safety constraints
        self.check_safety(request.target)
        self.history.append(request)

        start_time = datetime.now(UTC)
        if self.artificial_delay_sec > 0:
            time.sleep(self.artificial_delay_sec)

        ability_id = request.ability_id or (
            self.lookup_technique(request.technique_id)[0]
            if self.lookup_technique(request.technique_id)
            else f"mock-{request.technique_id}"
        )

        end_time = datetime.now(UTC)
        duration = (end_time - start_time).total_seconds()

        if self.simulate_failure:
            return DetonationResult(
                success=False,
                hunt_id=request.hunt_id,
                technique_id=request.technique_id,
                ability_id=ability_id,
                provider=self.name,
                start_time_utc=start_time.isoformat(),
                end_time_utc=end_time.isoformat(),
                duration_seconds=duration,
                exit_code=1,
                stdout="",
                stderr="Simulated adversary detonation error: execution failed on agent.",
                stage=DetonationStage.FAILED,
                cleanup_success=not self.simulate_cleanup_failure,
                cleanup_error="Cleanup failed" if self.simulate_cleanup_failure else None,
                error_message="Detonation failed due to simulated error condition.",
            )

        # Successful mock detonation
        cleanup_success = not self.simulate_cleanup_failure
        cleanup_error = "Mock cleanup failure simulated" if self.simulate_cleanup_failure else None

        # Synthesize realistic telemetry metadata
        is_psh = "powershell" in ability_id
        is_cloud = any(c in ability_id.lower() for c in ("aws", "gcp", "azure", "cloudtrail"))
        if is_cloud:
            category = "cloud"
            product = (
                "aws"
                if "aws" in ability_id.lower()
                else ("azure" if "azure" in ability_id.lower() else "gcp")
            )
        else:
            category = "process_creation"
            product = "windows" if is_psh else "linux"

        telemetry = [
            {
                "category": category,
                "product": product,
                "data_source": category,
                "technique_id": request.technique_id,
                "event_type": "Sysmon Event ID 1" if not is_cloud else "CloudTrail",
                "process_name": "powershell.exe" if is_psh else "bash",
                "Image": (
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    if is_psh
                    else "/bin/bash"
                ),
                "CommandLine": (
                    f"powershell.exe -ExecutionPolicy Bypass -Command mock_detonation --technique {request.technique_id}"
                    if is_psh
                    else f"/bin/bash -c mock_detonation --technique {request.technique_id}"
                ),
                "command_line": f"mock_detonation --technique {request.technique_id}",
                "timestamp_utc": start_time.isoformat(),
            }
        ]

        return DetonationResult(
            success=True,
            hunt_id=request.hunt_id,
            technique_id=request.technique_id,
            ability_id=ability_id,
            provider=self.name,
            start_time_utc=start_time.isoformat(),
            end_time_utc=end_time.isoformat(),
            duration_seconds=duration,
            exit_code=0,
            stdout=f"Mock detonation of {ability_id} executed successfully.",
            stderr="",
            stage=DetonationStage.COMPLETED,
            cleanup_success=cleanup_success,
            cleanup_error=cleanup_error,
            telemetry_signatures=telemetry,
            raw_details={"mock_execution": True, "request_params": request.params},
        )

    def cleanup(self, request: DetonationRequest) -> bool:
        self.cleanup_calls.append(request)
        return not self.simulate_cleanup_failure

    def health_check(self) -> dict[str, Any]:
        return {
            "status": "healthy",
            "provider": self.name,
            "catalog_techniques": len(MOCK_TECHNIQUE_CATALOG),
            "simulated_failure": self.simulate_failure,
        }
