"""MITRE CALDERA REST API Connector for Adversary Emulation.

Interacts with the MITRE CALDERA v4/v5 REST API to query adversary abilities by
MITRE ATT&CK Technique ID, launch scoped autonomous operations against lab agents,
monitor execution, and collect telemetry execution traces.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from hecate_runner.bas.base import (
    BASExecutionError,
    BASProvider,
    DetonationRequest,
    DetonationResult,
    DetonationStage,
)

log = logging.getLogger(__name__)


class CalderaConnector(BASProvider):
    """Connector for MITRE CALDERA adversary emulation platform."""

    name: str = "caldera"
    provider_type: str = "endpoint_bas"

    def __init__(
        self,
        base_url: str = "http://localhost:8888",
        api_key: str | None = None,
        agent_group: str = "staging",
        timeout_sec: int = 120,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
        client: httpx.Client | None = None,
    ):
        super().__init__(allowed_hosts=allowed_hosts, allowed_accounts=allowed_accounts)
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or ""
        self.agent_group = agent_group
        self.timeout_sec = timeout_sec
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        headers = {
            "Content-Type": "application/json",
            "KEY": self.api_key,
        }
        return httpx.Client(base_url=self.base_url, headers=headers, timeout=self.timeout_sec)

    def health_check(self) -> dict[str, Any]:
        """Verify CALDERA server API connectivity and active agent count."""
        try:
            client = self._get_client()
            resp = client.get("/api/v2/health")
            if resp.status_code == 200:
                health_data = resp.json()
            else:
                health_data = {"status": "reachable", "http_status": resp.status_code}

            # Check active agents
            agents_resp = client.get("/api/v2/agents")
            agents = agents_resp.json() if agents_resp.status_code == 200 else []
            staging_agents = [a.get("paw") for a in agents if a.get("group") == self.agent_group]

            return {
                "status": "healthy" if resp.status_code in (200, 204) else "degraded",
                "caldera_url": self.base_url,
                "agent_group": self.agent_group,
                "active_agents": len(agents),
                "staging_agents": staging_agents,
                "server_details": health_data,
            }
        except Exception as exc:
            log.warning("CALDERA health check failed: %s", exc)
            return {
                "status": "unreachable",
                "caldera_url": self.base_url,
                "error": str(exc),
            }

    def lookup_technique(self, technique_id: str) -> list[str]:
        """Query CALDERA for ability IDs associated with a MITRE ATT&CK technique."""
        try:
            client = self._get_client()
            resp = client.get("/api/v2/abilities")
            if resp.status_code != 200:
                log.warning("CALDERA /api/v2/abilities returned %d", resp.status_code)
                return []

            abilities = resp.json()
            matched = []
            tid_upper = technique_id.upper()
            for ab in abilities:
                if ab.get("technique_id", "").upper() == tid_upper:
                    ability_id = ab.get("ability_id")
                    if ability_id:
                        matched.append(ability_id)
            return matched
        except Exception as exc:
            log.error("Failed to lookup technique %s in CALDERA: %s", technique_id, exc)
            return []

    def detonate(self, request: DetonationRequest) -> DetonationResult:
        """Trigger an autonomous adversary operation in CALDERA."""
        # 1. Enforce safety checks
        self.check_safety(request.target)

        # 2. Resolve ability ID
        ability_id = request.ability_id
        if not ability_id:
            abilities = self.lookup_technique(request.technique_id)
            if not abilities:
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
                    stderr=f"No CALDERA ability found matching technique {request.technique_id}",
                    stage=DetonationStage.FAILED,
                    error_message=f"Technique {request.technique_id} has no mapped abilities in CALDERA.",
                )
            ability_id = abilities[0]

        start_time = datetime.now(UTC)
        op_name = (
            f"hecate_{request.hunt_id.lower()}_{request.technique_id.lower()}_{int(time.time())}"
        )

        client = self._get_client()

        # 3. Create the ephemeral operation
        op_payload = {
            "name": op_name,
            "adversary": {
                "adversary_id": "ad-hoc-hecate",
                "name": f"Hecate Ad-Hoc {request.technique_id}",
                "atomic_ordering": [ability_id],
            },
            "group": self.agent_group,
            "autonomous": 1,
            "auto_close": request.cleanup_on_finish,
        }

        try:
            op_resp = client.post("/api/v2/operations", json=op_payload)
            if op_resp.status_code not in (200, 201):
                err_msg = (
                    f"Failed to create CALDERA operation: {op_resp.status_code} - {op_resp.text}"
                )
                log.error(err_msg)
                end_time = datetime.now(UTC)
                return DetonationResult(
                    success=False,
                    hunt_id=request.hunt_id,
                    technique_id=request.technique_id,
                    ability_id=ability_id,
                    provider=self.name,
                    start_time_utc=start_time.isoformat(),
                    end_time_utc=end_time.isoformat(),
                    duration_seconds=(end_time - start_time).total_seconds(),
                    exit_code=1,
                    stdout="",
                    stderr=err_msg,
                    stage=DetonationStage.FAILED,
                    error_message=err_msg,
                )

            operation_data = op_resp.json()
            op_id = operation_data.get("id") or operation_data.get("operation_id")
            if not op_id:
                raise BASExecutionError("CALDERA operation created without valid operation ID")

            # 4. Poll operation to completion
            poll_start = time.time()
            poll_interval = 2.0
            completed_op: dict[str, Any] = {}
            op_finished = False

            while (time.time() - poll_start) < request.timeout_sec:
                status_resp = client.get(f"/api/v2/operations/{op_id}")
                if status_resp.status_code == 200:
                    completed_op = status_resp.json()
                    state = completed_op.get("state", "").lower()
                    if state in ("finished", "cleanup", "out_of_time"):
                        op_finished = True
                        break
                time.sleep(poll_interval)

            end_time = datetime.now(UTC)
            duration = (end_time - start_time).total_seconds()

            if not op_finished:
                return DetonationResult(
                    success=False,
                    hunt_id=request.hunt_id,
                    technique_id=request.technique_id,
                    ability_id=ability_id,
                    provider=self.name,
                    start_time_utc=start_time.isoformat(),
                    end_time_utc=end_time.isoformat(),
                    duration_seconds=duration,
                    exit_code=124,  # Standard timeout code
                    stdout="",
                    stderr=f"CALDERA operation {op_id} timed out after {request.timeout_sec}s",
                    stage=DetonationStage.FAILED,
                    raw_details={"operation_id": op_id, "last_state": completed_op.get("state")},
                    error_message=f"Operation timed out after {request.timeout_sec}s",
                )

            # 5. Extract links & results
            chain = completed_op.get("chain", [])
            link_outputs: list[str] = []
            link_errors: list[str] = []
            all_succeeded = True
            telemetry: list[dict[str, Any]] = []

            for link in chain:
                status = link.get("status", 0)
                cmd = link.get("command", "")
                link_id = link.get("id")
                paw = link.get("paw", "unknown")

                # Try fetching output for link
                output = ""
                if link_id:
                    try:
                        out_resp = client.get(f"/api/v2/operations/{op_id}/links/{link_id}/result")
                        if out_resp.status_code == 200:
                            output = out_resp.json().get("result", "")
                    except Exception:
                        output = link.get("output", "")

                if status != 0:
                    all_succeeded = False
                    link_errors.append(f"Link {link_id} on {paw} failed with status {status}")
                else:
                    link_outputs.append(f"Link {link_id} on {paw} executed: {output}")

                telemetry.append(
                    {
                        "data_source": "caldera_link",
                        "technique_id": request.technique_id,
                        "ability_id": ability_id,
                        "paw": paw,
                        "command": cmd,
                        "timestamp_utc": link.get("collect") or start_time.isoformat(),
                    }
                )

            return DetonationResult(
                success=all_succeeded and len(chain) > 0,
                hunt_id=request.hunt_id,
                technique_id=request.technique_id,
                ability_id=ability_id,
                provider=self.name,
                start_time_utc=start_time.isoformat(),
                end_time_utc=end_time.isoformat(),
                duration_seconds=duration,
                exit_code=0 if all_succeeded else 1,
                stdout="\n".join(link_outputs) or "Operation completed with no output.",
                stderr="\n".join(link_errors),
                stage=DetonationStage.COMPLETED,
                cleanup_success=completed_op.get("state") != "out_of_time",
                telemetry_signatures=telemetry,
                raw_details={"operation_id": op_id, "chain_length": len(chain)},
            )

        except Exception as exc:
            end_time = datetime.now(UTC)
            log.exception("Unexpected error detonating CALDERA operation: %s", exc)
            return DetonationResult(
                success=False,
                hunt_id=request.hunt_id,
                technique_id=request.technique_id,
                ability_id=ability_id,
                provider=self.name,
                start_time_utc=start_time.isoformat(),
                end_time_utc=end_time.isoformat(),
                duration_seconds=(end_time - start_time).total_seconds(),
                exit_code=1,
                stdout="",
                stderr=str(exc),
                stage=DetonationStage.FAILED,
                error_message=str(exc),
            )

    def cleanup(self, request: DetonationRequest) -> bool:
        """Trigger explicit cleanup for any lingering CALDERA operations."""
        # CALDERA auto_close handles link cleanup; explicit cleanup can send command if needed
        return True
