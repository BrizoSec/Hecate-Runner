"""Stratus Red Team Connector for Cloud Adversary Emulation.

Interacts with the DataDog Stratus Red Team CLI to execute cloud adversary simulations
against AWS, Azure, GCP, and Kubernetes staging environments, verifying that cloud
control plane telemetry (CloudTrail, GuardDuty, Activity Logs) is generated.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from hecate_runner.bas.base import (
    BASProvider,
    DetonationRequest,
    DetonationResult,
    DetonationStage,
)

log = logging.getLogger(__name__)

# Standard mapping of MITRE ATT&CK techniques to Stratus Red Team attack IDs
STRATUS_TECHNIQUE_MAP: dict[str, list[str]] = {
    # AWS
    "T1562.008": ["aws.defense-evasion.cloudtrail-stop"],
    "T1562.001": ["aws.defense-evasion.cloudtrail-delete"],
    "T1098.001": ["aws.persistence.create-admin-access-key"],
    "T1136.003": ["aws.persistence.create-iam-user"],
    "T1078.004": ["aws.privilege-escalation.iam-backdoor-role"],
    "T1530": ["aws.exfiltration.s3-bucket-dump"],
    "T1485": ["aws.impact.s3-delete-bucket"],
    "T1552.005": ["aws.credential-access.ec2-get-password-data"],
    "T1059.009": ["aws.execution.ec2-user-data"],
    # Azure
    "T1098": ["azure.persistence.add-service-principal-credentials"],
    "T1059": ["azure.execution.vm-run-command"],
    "T1562": ["azure.defense-evasion.delete-diagnostic-settings"],
    # Kubernetes
    "T1610": ["k8s.privilege-escalation.privileged-pod"],
    "T1059.004": ["k8s.execution.curl-metadata-service"],
}


class StratusConnector(BASProvider):
    """Connector for Stratus Red Team cloud adversary emulation."""

    name: str = "stratus"
    provider_type: str = "cloud_bas"

    def __init__(
        self,
        binary_path: str = "stratus-red-team",
        timeout_sec: int = 300,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
        runner_fn: Callable[[list[str], int], subprocess.CompletedProcess[str]] | None = None,
    ):
        super().__init__(allowed_hosts=allowed_hosts, allowed_accounts=allowed_accounts)
        self.binary_path = binary_path
        self.timeout_sec = timeout_sec
        self._runner_fn = runner_fn

    def _run_cmd(self, args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        """Execute a stratus-red-team CLI command."""
        if self._runner_fn is not None:
            return self._runner_fn(args, timeout)

        cmd = [self.binary_path, *args]
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def health_check(self) -> dict[str, Any]:
        """Verify binary availability and installed version."""
        binary_found = bool(
            self._runner_fn is not None
            or shutil.which(self.binary_path)
            or os.path.isfile(self.binary_path)
        )
        version_str = "unknown"
        if binary_found:
            try:
                proc = self._run_cmd(["version"], timeout=10)
                if proc.returncode == 0:
                    version_str = proc.stdout.strip()
            except Exception as exc:
                version_str = f"error: {exc}"

        return {
            "status": "healthy" if binary_found else "uninstalled",
            "binary_path": self.binary_path,
            "binary_found": binary_found,
            "version": version_str,
            "mapped_techniques": len(STRATUS_TECHNIQUE_MAP),
        }

    def lookup_technique(self, technique_id: str) -> list[str]:
        """Map a MITRE ATT&CK Technique ID to supported Stratus Red Team IDs."""
        return STRATUS_TECHNIQUE_MAP.get(technique_id.upper(), [])

    def detonate(self, request: DetonationRequest) -> DetonationResult:
        """Execute the 3-step Stratus lifecycle: Warmup -> Detonate -> Cleanup."""
        # 1. Strict safety check
        self.check_safety(request.target)

        # 2. Resolve Stratus attack ID
        ability_id = request.ability_id
        if not ability_id:
            matched = self.lookup_technique(request.technique_id)
            if not matched:
                return DetonationResult(
                    success=False,
                    hunt_id=request.hunt_id,
                    technique_id=request.technique_id,
                    ability_id="unknown",
                    provider=self.name,
                    start_time_utc=datetime.now(UTC).isoformat(),
                    end_time_utc=datetime.now(UTC).isoformat(),
                    duration_seconds=0.0,
                    exit_code=1,
                    stdout="",
                    stderr=f"No Stratus Red Team detonator found for technique {request.technique_id}",
                    stage=DetonationStage.FAILED,
                    error_message=f"Technique {request.technique_id} is not supported by Stratus Red Team.",
                )
            ability_id = matched[0]

        start_time = datetime.now(UTC)
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        current_stage = DetonationStage.WARMING_UP
        cleanup_success = True
        cleanup_error: str | None = None
        exit_code = 0
        warmup_succeeded = False

        try:
            # 3. Stage 1: Warmup (provision test infrastructure)
            log.info("Stratus Red Team warmup: %s", ability_id)
            warmup_proc = self._run_cmd(["warmup", ability_id], timeout=self.timeout_sec)
            stdout_parts.append(f"--- WARMUP ---\n{warmup_proc.stdout}")
            if warmup_proc.returncode != 0:
                stderr_parts.append(f"Warmup failed: {warmup_proc.stderr}")
                return DetonationResult(
                    success=False,
                    hunt_id=request.hunt_id,
                    technique_id=request.technique_id,
                    ability_id=ability_id,
                    provider=self.name,
                    start_time_utc=start_time.isoformat(),
                    end_time_utc=datetime.now(UTC).isoformat(),
                    duration_seconds=(datetime.now(UTC) - start_time).total_seconds(),
                    exit_code=warmup_proc.returncode,
                    stdout="\n".join(stdout_parts),
                    stderr="\n".join(stderr_parts),
                    stage=DetonationStage.FAILED,
                    error_message=f"Stratus warmup failed with code {warmup_proc.returncode}",
                )
            warmup_succeeded = True

            # 4. Stage 2: Detonate (trigger the cloud adversary behavior)
            current_stage = DetonationStage.DETONATING
            log.info("Stratus Red Team detonate: %s", ability_id)
            detonate_proc = self._run_cmd(["detonate", ability_id], timeout=self.timeout_sec)
            stdout_parts.append(f"--- DETONATE ---\n{detonate_proc.stdout}")
            if detonate_proc.returncode != 0:
                stderr_parts.append(f"Detonate failed: {detonate_proc.stderr}")
                exit_code = detonate_proc.returncode
            else:
                current_stage = DetonationStage.COMPLETED

        except subprocess.TimeoutExpired as exc:
            stderr_parts.append(f"Stratus command timed out: {exc}")
            exit_code = 124
            current_stage = DetonationStage.FAILED
        except Exception as exc:
            stderr_parts.append(f"Stratus execution exception: {exc}")
            exit_code = 1
            current_stage = DetonationStage.FAILED
        finally:
            # 5. Stage 3: Mandatory Cleanup (destroy cloud infrastructure)
            if request.cleanup_on_finish and warmup_succeeded:
                log.info("Stratus Red Team cleanup: %s", ability_id)
                try:
                    cleanup_proc = self._run_cmd(["cleanup", ability_id], timeout=self.timeout_sec)
                    stdout_parts.append(f"--- CLEANUP ---\n{cleanup_proc.stdout}")
                    if cleanup_proc.returncode != 0:
                        cleanup_success = False
                        cleanup_error = f"Cleanup failed with code {cleanup_proc.returncode}: {cleanup_proc.stderr}"
                        stderr_parts.append(cleanup_error)
                except Exception as clean_exc:
                    cleanup_success = False
                    cleanup_error = f"Cleanup threw exception: {clean_exc}"
                    stderr_parts.append(cleanup_error)

        end_time = datetime.now(UTC)
        duration = (end_time - start_time).total_seconds()
        is_success = (exit_code == 0) and cleanup_success

        # Generate telemetry hints based on technique
        telemetry = [
            {
                "data_source": "cloud_control_plane",
                "technique_id": request.technique_id,
                "ability_id": ability_id,
                "cloud_provider": ability_id.split(".")[0],
                "event_type": ability_id.split(".")[-1],
                "timestamp_utc": start_time.isoformat(),
            }
        ]

        return DetonationResult(
            success=is_success,
            hunt_id=request.hunt_id,
            technique_id=request.technique_id,
            ability_id=ability_id,
            provider=self.name,
            start_time_utc=start_time.isoformat(),
            end_time_utc=end_time.isoformat(),
            duration_seconds=duration,
            exit_code=exit_code,
            stdout="\n".join(stdout_parts),
            stderr="\n".join(stderr_parts),
            stage=current_stage,
            cleanup_success=cleanup_success,
            cleanup_error=cleanup_error,
            telemetry_signatures=telemetry,
            raw_details={"ability_id": ability_id, "cloud_platform": request.target.platform},
            error_message="\n".join(stderr_parts) if not is_success else None,
        )

    def cleanup(self, request: DetonationRequest) -> bool:
        """Explicit on-demand cleanup invocation."""
        ability_id = request.ability_id
        if not ability_id:
            matched = self.lookup_technique(request.technique_id)
            if not matched:
                return False
            ability_id = matched[0]

        try:
            proc = self._run_cmd(["cleanup", ability_id], timeout=self.timeout_sec)
            return proc.returncode == 0
        except Exception as exc:
            log.error("Failed explicit Stratus cleanup for %s: %s", ability_id, exc)
            return False
