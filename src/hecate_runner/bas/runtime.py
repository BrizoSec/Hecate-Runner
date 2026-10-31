"""Scoped lab automation and private, durable BAS run evidence."""

from __future__ import annotations

import fcntl
import json
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.bas.approved import APPROVED_PROCEDURES, ApprovedProcedure
from hecate_runner.bas.base import DetonationRequest, DetonationTarget, SafetyViolationError
from hecate_runner.bas.sensor import LabProcessSensor
from hecate_runner.bas.verifier import DetectionVerifier
from hecate_runner.config import Settings


def save_bas_record(settings: Settings, record: dict[str, Any]) -> dict[str, Any]:
    """Keep execution evidence outside Git and expose nonsecret runtime status."""
    record.setdefault("run_id", uuid.uuid4().hex)
    record.setdefault("verified_at", datetime.now(UTC).isoformat())
    root = settings.hecate_workspace / ".hecate" / "bas"
    atomic_write_text(
        root / "runs" / f"{record['run_id']}.json", json.dumps(record, indent=2), mode=0o600
    )
    atomic_write_text(
        root / "state.json",
        json.dumps(
            {
                "enabled": settings.bas_enabled,
                "auto_execute_live": settings.bas_auto_execute_live,
                "provider": settings.bas_mode,
                "telemetry": settings.bas_telemetry,
                "allowed_techniques": settings.bas_auto_techniques,
                "last_status": record.get("status"),
                "last_reason": record.get("reason", ""),
                "updated_at": record["verified_at"],
            },
            indent=2,
        ),
        mode=0o600,
    )
    return record


def skipped_bas(settings: Settings, hunt_id: str, reason: str) -> dict[str, Any]:
    return save_bas_record(
        settings,
        {
            "hunt_id": hunt_id,
            "provider": settings.bas_mode,
            "status": "skipped",
            "reason": reason,
            "notes": [reason],
            "telemetry_arrived": False,
            "rule_triggered": False,
        },
    )


def run_approved_validation(
    settings: Settings, hunt_id: str, procedure: ApprovedProcedure, rule_yaml: str
) -> dict[str, Any]:
    """Execute one pinned read-only procedure and evaluate independently observed events."""
    from hecate_runner.bas import get_bas_provider

    root = settings.hecate_workspace / ".hecate" / "bas"
    root.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "hunt_id": hunt_id,
        "provider": "caldera",
        "technique_id": procedure.technique_id,
        "ability_id": procedure.ability_id,
        "backend": "lab_process",
        "verification_scope": "local_sensor_sigma",
        "purpose": "sensor_control" if hunt_id == "LAB-CHECK" else "hunt_validation",
        "telemetry_arrived": False,
        "rule_triggered": False,
    }
    with (root / "execution.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return skipped_bas(settings, hunt_id, "Another BAS lab validation is running.")
        try:
            if (
                settings.bas_mode != "caldera"
                or settings.bas_telemetry != "lab_process"
                or settings.bas_fallback_to_mock
                or not settings.bas_linux_host
                or settings.bas_linux_host not in settings.bas_allowed_hosts
                or procedure.technique_id not in settings.bas_auto_techniques
                or APPROVED_PROCEDURES.get(procedure.technique_id) != procedure
                or urlparse(settings.caldera_url).hostname not in {"localhost", "127.0.0.1", "::1"}
                or settings.caldera_agent_group != "hecate-local-lab"
            ):
                raise SafetyViolationError(
                    "Approved automation requires CALDERA, an allowlisted Linux lab, and its process sensor."
                )
            sensor = LabProcessSensor(settings.bas_sensor_container, settings.bas_linux_host)
            sensor.preflight()
            provider = get_bas_provider("caldera", settings)
            request = DetonationRequest(
                hunt_id=hunt_id,
                technique_id=procedure.technique_id,
                ability_id=procedure.ability_id,
                platform="linux",
                target=DetonationTarget(
                    environment="lab", platform="linux", host=settings.bas_linux_host
                ),
                # Allow two 60s agent beacons and scheduling slack.
                timeout_sec=180,
                params={"approved_only": True},
            )
            detonation = provider.detonate(request)
            events = sensor.collect(detonation, procedure.argv) if detonation.success else []
            verification = DetectionVerifier().verify_detonation(
                detonation, rule_yaml=rule_yaml, raw_events=events, backend="lab_process"
            )
            record.update(verification.to_dict())
            record["duration_seconds"] = detonation.duration_seconds
            record["cleanup_success"] = detonation.cleanup_success
            record["sensor_events_count"] = len(events)
            if not detonation.cleanup_success:
                record.update(status="error", rule_triggered=False)
                record["notes"].append("Remote operation cleanup was not confirmed.")
        except Exception as exc:
            record.update(status="error", reason=str(exc), notes=[str(exc)])
        return save_bas_record(settings, record)
