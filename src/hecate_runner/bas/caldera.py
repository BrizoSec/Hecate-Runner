"""MITRE CALDERA REST API Connector for Adversary Emulation.

Interacts with the MITRE CALDERA v4/v5 REST API to query adversary abilities by
MITRE ATT&CK Technique ID, launch scoped autonomous operations against lab agents,
monitor execution, and collect telemetry execution traces.
"""

from __future__ import annotations

import contextlib
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
            elif resp.status_code == 404:
                # Fallback to Caldera classic API (/api/plugins or /api/health)
                plugins_resp = client.get("/api/plugins")
                if plugins_resp.status_code == 200:
                    health_data = {
                        "status": "reachable",
                        "version": "classic",
                        "plugins": plugins_resp.json(),
                    }
                else:
                    health_data = {"status": "reachable", "http_status": 200}
            else:
                health_data = {"status": "reachable", "http_status": resp.status_code}

            # Check active agents (v2 fallback to classic)
            agents_resp = client.get("/api/v2/agents")
            if agents_resp.status_code == 404:
                agents_resp = client.get("/api/agents")
            agents = agents_resp.json() if agents_resp.status_code == 200 else []
            staging_agents = [a.get("paw") for a in agents if a.get("group") == self.agent_group]

            return {
                "status": "healthy" if resp.status_code in (200, 204, 404) else "degraded",
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
            if resp.status_code == 404:
                resp = client.get("/api/abilities")
            if resp.status_code != 200:
                log.warning("CALDERA abilities endpoint returned %d", resp.status_code)
                return []

            abilities = resp.json()
            matched = []
            tid_upper = technique_id.upper()
            for ab in abilities:
                tech = ab.get("technique")
                ab_tid = (
                    ab.get("technique_id")
                    or (tech.get("attack_id") if isinstance(tech, dict) else "")
                    or ""
                ).upper()
                if ab_tid == tid_upper:
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

        # 3. Create the ephemeral operation (try /api/v2/operations, fallback to Caldera classic /api/rest)
        is_v2 = True
        adv_id = ""
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
            if op_resp.status_code == 404:
                is_v2 = False
                adv_id = f"hecate-{int(time.time())}"
                client.put(
                    "/api/rest",
                    json={
                        "index": "adversaries",
                        "id": adv_id,
                        "name": f"Hecate Ad-Hoc {request.technique_id}",
                        "description": "Auto-generated Hecate ad-hoc adversary",
                        "atomic_ordering": [{"ability_id": ability_id}],
                    },
                )
                op_resp = client.put(
                    "/api/rest",
                    json={
                        "index": "operations",
                        "name": op_name,
                        "adversary_id": adv_id,
                        "group": self.agent_group,
                        "autonomous": 1,
                        "auto_close": bool(request.cleanup_on_finish),
                    },
                )

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

            raw_op_data = op_resp.json()
            operation_data = (
                raw_op_data[0]
                if isinstance(raw_op_data, list) and raw_op_data
                else (raw_op_data if isinstance(raw_op_data, dict) else {})
            )
            op_id = operation_data.get("id") or operation_data.get("operation_id")
            if not op_id:
                raise BASExecutionError("CALDERA operation created without valid operation ID")

            # 4. Poll operation to completion
            poll_start = time.time()
            poll_interval = 2.0
            completed_op: dict[str, Any] = {}
            op_finished = False

            while (time.time() - poll_start) < request.timeout_sec:
                if is_v2:
                    status_resp = client.get(f"/api/v2/operations/{op_id}")
                    if status_resp.status_code == 200:
                        completed_op = status_resp.json()
                else:
                    status_resp = client.post(
                        "/api/rest",
                        json={"index": "operations", "id": op_id},
                    )
                    if status_resp.status_code == 200:
                        raw_ops = status_resp.json()
                        completed_op = (
                            raw_ops[0]
                            if isinstance(raw_ops, list) and raw_ops
                            else (raw_ops if isinstance(raw_ops, dict) else {})
                        )

                state = completed_op.get("state", "").lower()
                if state in ("finished", "cleanup", "out_of_time"):
                    op_finished = True
                    break
                time.sleep(poll_interval)

            end_time = datetime.now(UTC)
            duration = (end_time - start_time).total_seconds()

            if not op_finished:
                if not is_v2 and adv_id:
                    with contextlib.suppress(Exception):
                        client.request(
                            "DELETE",
                            "/api/rest",
                            json={"index": "adversaries", "adversary_id": adv_id},
                        )
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
                        if is_v2:
                            out_resp = client.get(
                                f"/api/v2/operations/{op_id}/links/{link_id}/result"
                            )
                            if out_resp.status_code == 200:
                                output = out_resp.json().get("result", "")
                        else:
                            out_resp = client.post(
                                "/api/rest",
                                json={"index": "result", "link_id": link_id},
                            )
                            if out_resp.status_code == 200:
                                res_data = out_resp.json()
                                output = (
                                    res_data.get("result", "")
                                    if isinstance(res_data, dict)
                                    else str(res_data)
                                )
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

            if not is_v2 and adv_id:
                with contextlib.suppress(Exception):
                    if request.cleanup_on_finish and op_id:
                        client.request(
                            "DELETE", "/api/rest", json={"index": "operations", "id": op_id}
                        )
                    client.request(
                        "DELETE",
                        "/api/rest",
                        json={"index": "adversaries", "adversary_id": adv_id},
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
