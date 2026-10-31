#!/usr/bin/env python3
"""Migrate the installed lab controller to nonroot with private state and rollback.

Run with the Runner virtual environment after building deploy/caldera/Dockerfile.
State and credentials are copied into private named volumes, never into images.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import httpx
import yaml

from hecate_runner.bas.approved import APPROVED_PROCEDURES, validate_approved_ability
from hecate_runner.bas.controller import CONTROLLER_STATE_PATHS, CONTROLLER_USER
from hecate_runner.config import Settings

IMAGE = "hecate-caldera:nonroot"
UID = CONTROLLER_USER
PATHS = CONTROLLER_STATE_PATHS


def command(*args: str, timeout: int = 60) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=timeout).stdout


def inspect(name: str) -> dict:
    return json.loads(command("docker", "inspect", name))[0]


def client(settings: Settings, port: int) -> httpx.Client:
    return httpx.Client(
        base_url=f"http://127.0.0.1:{port}",
        headers={"KEY": settings.caldera_api_key or ""},
        timeout=4,
    )


def inventory(settings: Settings, port: int) -> dict[str, set[str]]:
    with client(settings, port) as api:
        abilities = api.get("/api/abilities")
        abilities.raise_for_status()
        by_id = {a["ability_id"]: a for a in abilities.json()}
        for procedure in APPROVED_PROCEDURES.values():
            validate_approved_ability(by_id[procedure.ability_id], procedure)
        operations = api.post("/api/rest", json={"index": "operations"})
        operations.raise_for_status()
        agents = api.get("/api/agents")
        agents.raise_for_status()
        if any(o.get("state") in {"running", "run_one_link", "cleanup"} for o in operations.json()):
            raise RuntimeError("Live operations are running; migration refused")
        return {
            "abilities": set(by_id),
            "operations": {o["id"] for o in operations.json()},
            "agents": {a["paw"] for a in agents.json()},
        }


def wait_ready(settings: Settings, port: int, before: dict, name: str) -> dict:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if not inspect(name)["State"]["Running"]:
            raise RuntimeError(f"{name} exited during startup; inspect private migration logs")
        try:
            actual = inventory(settings, port)
            if any(not ids <= actual[key] for key, ids in before.items()):
                raise RuntimeError("Controller inventory lost state during migration")
            return actual
        except (httpx.HTTPError, KeyError):
            time.sleep(1)
    raise RuntimeError("Controller readiness timed out")


def create(name: str, port: int, volumes: dict, production: bool) -> None:
    args = [
        "docker",
        "create",
        "--name",
        name,
        "--hostname",
        "caldera",
        "--user",
        UID,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--memory",
        "1g",
        "--memory-swap",
        "1g",
        "--cpus",
        "1",
        "--pids-limit",
        "128",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "nofile=1024:1024",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=128m,uid=10001,gid=10001,mode=1777",
        "--network",
        "bridge",
        "--publish",
        f"127.0.0.1:{port}:8888",
        "--stop-signal",
        "SIGINT",
        "--stop-timeout",
        "30",
        "--restart",
        "unless-stopped" if production else "no",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=3",
        "--label",
        "hecate.role=caldera-controller",
    ]
    for key, target in PATHS.items():
        args.extend(["--mount", f"type=volume,source={volumes[key]},target={target}"])
    command(*args, IMAGE)
    if production:
        command("docker", "network", "connect", "--alias", "caldera", "hecate-bas-lab", name)


def save_logs(name: str, backup: Path) -> None:
    result = subprocess.run(["docker", "logs", name], text=True, capture_output=True)
    path = backup / f"{name}.log"
    path.write_text(result.stdout + result.stderr)
    path.chmod(0o600)


def main() -> None:
    os.umask(0o077)
    settings = Settings()
    old = inspect("caldera")
    if old["Config"].get("User"):
        raise RuntimeError(
            "Installed controller already has a configured user; inspect before migrating"
        )
    if old.get("Mounts"):
        raise RuntimeError(
            "Unexpected source mounts; this migration requires the reviewed unmounted controller"
        )
    image = json.loads(command("docker", "image", "inspect", IMAGE))[0]
    if image["Config"].get("User") != UID:
        raise RuntimeError("Prepared image is not the reviewed nonroot image")
    before = inventory(settings, 8888)
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = Path.home() / ".config/hecate/caldera-nonroot" / stamp
    backup.mkdir(mode=0o700, parents=True)
    (backup / "source-inspect.json").write_text(json.dumps(old, indent=2))
    (backup / "inventory-before.json").write_text(
        json.dumps({k: sorted(v) for k, v in before.items()}, indent=2)
    )
    lock_path = settings.hecate_workspace / ".hecate/bas/execution.lock"
    candidate = "hecate-caldera-candidate-" + stamp.lower()
    initializer = "hecate-caldera-init-" + stamp.lower()
    old_name = "caldera-before-nonroot-" + stamp.lower()
    stopped = renamed = production_created = False
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            command("systemctl", "--user", "stop", "caldera-sandcat.service")
            stopped = True
            command(
                "docker", "stop", "--signal", "SIGINT", "--timeout", "30", "caldera", timeout=40
            )
            for key, source in PATHS.items():
                present = subprocess.run(
                    ["docker", "cp", f"caldera:{source}", str(backup / key)], capture_output=True
                )
                if present.returncode and key in {"conf", "data", "docs", "gocat", "payloads"}:
                    raise RuntimeError(f"Required state could not be copied: {key}")
                (backup / key).mkdir(exist_ok=True)
            config = yaml.safe_load((backup / "conf/local.yml").read_text())
            if config.get("api_key_red") != settings.caldera_api_key:
                raise RuntimeError(
                    "API credentials do not match the preserved workspace configuration"
                )
            if not (backup / "data/object_store").exists():
                raise RuntimeError(
                    "Graceful shutdown did not produce the object store; refusing to lose state"
                )
            volumes = {key: f"hecate-caldera-{key}-{stamp.lower()}" for key in PATHS}
            for volume in volumes.values():
                command("docker", "volume", "create", volume)
            args = [
                "docker",
                "create",
                "--name",
                initializer,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "DAC_OVERRIDE",
                "--cap-add",
                "FOWNER",
                "--security-opt",
                "no-new-privileges=true",
                "--user",
                "0:0",
                "--entrypoint",
                "python3",
            ]
            for key, volume in volumes.items():
                args.extend(["--mount", f"type=volume,source={volume},target=/state/{key}"])
            init = """import os,pathlib,stat
for root in pathlib.Path('/state').iterdir():
 for directory,dirs,files in os.walk(root):
  for path in [pathlib.Path(directory),*[pathlib.Path(directory)/f for f in files]]:
   if path.is_symlink():continue
   path.chmod(0o700 if path.is_dir() or path.stat().st_mode & 0o111 else 0o600)
   os.chown(path,10001,10001)
# Keep documentation's Python configuration immutable while allowing generated output.
root=pathlib.Path('/state/docs')
for directory,dirs,files in os.walk(root):
 for path in [pathlib.Path(directory),*[pathlib.Path(directory)/f for f in files]]:
  if path.is_symlink():continue
  relative=path.relative_to(root)
  if relative.parts and relative.parts[0] in {'_build','_generated','plugins'}:continue
  if relative==pathlib.Path('index.rst'):continue
  os.chown(path,0,0);path.chmod(0o555 if path.is_dir() else 0o444)
"""
            command(*args, old["Config"]["Image"], "-c", init)
            for key in PATHS:
                command("docker", "cp", str(backup / key) + "/.", f"{initializer}:/state/{key}")
            command("docker", "start", "--attach", initializer)
            command("docker", "rm", initializer)
            create(candidate, 18889, volumes, False)
            command("docker", "start", candidate)
            wait_ready(settings, 18889, before, candidate)
            save_logs(candidate, backup)
            command(
                "docker", "stop", "--signal", "SIGINT", "--timeout", "30", candidate, timeout=40
            )
            command("docker", "rm", candidate)
            command("docker", "rename", "caldera", old_name)
            renamed = True
            production_created = True
            create("caldera", 8888, volumes, True)
            command("docker", "start", "caldera")
            after = wait_ready(settings, 8888, before, "caldera")
            command("systemctl", "--user", "start", "caldera-sandcat.service")
            (backup / "migration.json").write_text(
                json.dumps(
                    {
                        "status": "complete",
                        "old_container": old_name,
                        "volumes": volumes,
                        "image": image["Id"],
                        "config_sha256": hashlib.sha256(
                            (backup / "conf/local.yml").read_bytes()
                        ).hexdigest(),
                        "counts_before": {k: len(v) for k, v in before.items()},
                        "counts_after": {k: len(v) for k, v in after.items()},
                    },
                    indent=2,
                )
            )
            print(
                "Nonroot controller active; credentials, procedures, agents, and operation inventory preserved."
            )
            print("Private backup:", backup)
            print("Previous stopped controller:", old_name)
        except Exception:
            for name in (initializer, candidate):
                subprocess.run(["docker", "rm", "--force", name], capture_output=True)
            if production_created:
                save_logs("caldera", backup)
                subprocess.run(["docker", "rm", "--force", "caldera"], capture_output=True)
            if renamed:
                command("docker", "rename", old_name, "caldera")
            if stopped:
                command("docker", "start", "caldera")
            command("systemctl", "--user", "start", "caldera-sandcat.service")
            print(
                "Migration did not pass verification; previous controller restored. Private backup:",
                backup,
            )
            raise


if __name__ == "__main__":
    main()
