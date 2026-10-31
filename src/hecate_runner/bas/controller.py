"""Required isolation for the local controller used by approved automation."""

from __future__ import annotations

from typing import Any

from hecate_runner.bas.base import SafetyViolationError

CONTROLLER_USER = "10001:10001"
CONTROLLER_STATE_PATHS = {
    "conf": "/usr/src/app/conf",
    "data": "/usr/src/app/data",
    "docs": "/usr/src/app/plugins/fieldmanual/sphinx-docs",
    "gocat": "/usr/src/app/plugins/sandcat/gocat",
    "payloads": "/usr/src/app/plugins/sandcat/payloads",
    "events": "/tmp/event_logs",
    "reports": "/tmp/reports",
    "exfil": "/tmp/caldera",
}


def validate_controller(container: dict[str, Any]) -> None:
    """Fail closed if the local controller loses its reviewed runtime profile."""
    config = container.get("Config") or {}
    host = container.get("HostConfig") or {}
    mounts = container.get("Mounts") or []
    bindings = host.get("PortBindings") or {}
    if (
        not container.get("State", {}).get("Running")
        or config.get("User") != CONTROLLER_USER
        or (config.get("Labels") or {}).get("hecate.role") != "caldera-controller"
        or not host.get("ReadonlyRootfs")
        or host.get("Privileged")
        or "ALL" not in (host.get("CapDrop") or [])
        or host.get("CapAdd")
        or "no-new-privileges=true" not in (host.get("SecurityOpt") or [])
        or any("unconfined" in s for s in host.get("SecurityOpt") or [])
        or host.get("PidMode") == "host"
        or host.get("IpcMode") == "host"
        or host.get("Memory", 0) not in range(1, 1073741825)
        or host.get("NanoCpus", 0) not in range(1, 1000000001)
        or host.get("PidsLimit", 0) not in range(1, 129)
        or set(bindings) != {"8888/tcp"}
        or bindings.get("8888/tcp") != [{"HostIp": "127.0.0.1", "HostPort": "8888"}]
        or set(container.get("NetworkSettings", {}).get("Networks", {}))
        != {"bridge", "hecate-bas-lab"}
        or any(m.get("Type") != "volume" for m in mounts)
        or {m.get("Destination") for m in mounts} != set(CONTROLLER_STATE_PATHS.values())
    ):
        raise SafetyViolationError(
            "CALDERA controller is not the reviewed nonroot, isolated local deployment."
        )
