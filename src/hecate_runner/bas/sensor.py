"""Independent execve observation inside the isolated Linux BAS container.

strace supervises the agent and records successful process executions. CALDERA
link records are deliberately not used as detection telemetry. This is local
sensor evidence evaluated with Sigma, not evidence of a SIEM alert.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
import subprocess
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from hecate_runner.bas.base import DetonationResult, SafetyViolationError

TRACE_PATH = "/tmp/hecate-exec.trace"
SENSOR_ENTRYPOINT = [
    "/usr/bin/strace",
    "-f",
    "-qq",
    "-ttt",
    "-s",
    "8192",
    "-e",
    "trace=execve,execveat",
    "-e",
    "signal=none",
    "-o",
    TRACE_PATH,
    "/usr/local/bin/sandcat",
]
_EXEC = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<time>\d+\.\d+)\s+execve\("
    r'(?P<path>"(?:\\.|[^"\\])*")\s*,\s*'
    r"(?P<args>\[.*?\])\s*,"
)
_RESUMED = re.compile(r"^\s*(\d+)\s+\d+\.\d+\s+<\.\.\. execve resumed>.*= 0$")


def parse_exec_trace(
    text: str, *, start: float, end: float, host: str, command: str | tuple[str, ...]
) -> list[dict[str, Any]]:
    """Return successful, bounded executions of the exact approved command."""
    events: list[dict[str, Any]] = []
    pending: dict[str, dict[str, Any]] = {}
    expected = list(shlex.split(command) if isinstance(command, str) else command)
    if not expected:
        return []
    for line in text.splitlines():
        match = _EXEC.match(line)
        if match:
            try:
                timestamp = float(match["time"])
                image = ast.literal_eval(match["path"])
                argv = ast.literal_eval(match["args"])
            except (ValueError, SyntaxError):
                continue
            if (
                not start <= timestamp <= end
                or not isinstance(argv, list)
                or argv != expected
                or PurePosixPath(image).name != PurePosixPath(expected[0]).name
            ):
                continue
            event = {
                "data_source": "process_creation",
                "product": "linux",
                "sensor": "lab_execve",
                "Computer": host,
                "Image": image,
                "CommandLine": shlex.join(argv),
                "ProcessId": int(match["pid"]),
                "UtcTime": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            }
            if line.endswith("= 0"):
                events.append(event)
            elif "<unfinished ...>" in line:
                pending[match["pid"]] = event
        else:
            resumed = _RESUMED.match(line)
            if resumed and resumed[1] in pending:
                events.append(pending.pop(resumed[1]))
    return events


class LabProcessSensor:
    """Read a dedicated container's process trace after validating its isolation."""

    def __init__(self, container: str, host: str):
        self.container = container
        self.host = host
        self.container_id = ""

    @staticmethod
    def _docker(*args: str) -> str:
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=10, check=True
        )
        return result.stdout

    def preflight(self) -> None:
        """Fail closed before scheduling if the target or sensor differs."""
        container = json.loads(self._docker("inspect", self.container))[0]
        config = container["Config"]
        host = container["HostConfig"]
        networks = container["NetworkSettings"]["Networks"]
        tmp_options = set((host.get("Tmpfs") or {}).get("/tmp", "").split(","))
        limits = {item["Name"]: item for item in host.get("Ulimits") or []}
        limits_ok = (
            limits.get("core", {}).get("Hard") == 0
            and limits.get("core", {}).get("Soft") == 0
            and limits.get("nofile", {}).get("Hard", 0) in range(1, 257)
            and limits.get("nofile", {}).get("Soft", 0) in range(1, 257)
            and limits.get("fsize", {}).get("Hard", 0) in range(1, 16777217)
            and limits.get("fsize", {}).get("Soft", 0) in range(1, 16777217)
        )
        if (
            not container["State"]["Running"]
            or config.get("Hostname") != self.host
            or config.get("User") != "65534:65534"
            or config.get("Entrypoint") != SENSOR_ENTRYPOINT
            or config.get("Cmd")
            != [
                "-server",
                "http://caldera:8888",
                "-group",
                "hecate-local-lab",
                "-paw",
                "hecate-local-sandbox",
            ]
            or not host.get("ReadonlyRootfs")
            or host.get("Privileged")
            or "ALL" not in (host.get("CapDrop") or [])
            or host.get("CapAdd")
            or "no-new-privileges=true" not in (host.get("SecurityOpt") or [])
            or any("unconfined" in s for s in host.get("SecurityOpt") or [])
            or container.get("Mounts")
            or host.get("PidMode") == "host"
            or host.get("IpcMode") == "host"
            or host.get("PortBindings")
            or set(networks) != {"hecate-bas-lab"}
            or host.get("PidsLimit", 0) not in range(1, 129)
            or host.get("Memory", 0) not in range(1, 268435457)
            or host.get("NanoCpus", 0) not in range(1, 500000001)
            or not {"rw", "nosuid", "nodev", "noexec"} <= tmp_options
            or not limits_ok
        ):
            raise SafetyViolationError("BAS lab isolation or process sensor preflight failed.")
        network = json.loads(self._docker("network", "inspect", "hecate-bas-lab"))[0]
        if not network.get("Internal"):
            raise SafetyViolationError("BAS lab network must be internal.")
        self.container_id = container["Id"]
        # Readiness: the tracer must have observed the agent's initial exec.
        trace = self._docker("exec", self.container_id, "head", "-c", "8192", TRACE_PATH)
        if 'execve("/usr/local/bin/sandcat"' not in trace or "= 0" not in trace:
            raise SafetyViolationError("BAS process sensor is not recording executions.")

    def collect(
        self, detonation: DetonationResult, command: str | tuple[str, ...]
    ) -> list[dict[str, Any]]:
        if not self.container_id:
            raise SafetyViolationError("BAS process sensor was not checked before execution.")
        # Bounded read; newest trace records remain at the end of the file.
        trace = self._docker("exec", self.container_id, "tail", "-c", "4194304", TRACE_PATH)
        start = datetime.fromisoformat(detonation.start_time_utc).timestamp()
        end = datetime.fromisoformat(detonation.end_time_utc).timestamp()
        return parse_exec_trace(trace, start=start, end=end, host=self.host, command=command)
