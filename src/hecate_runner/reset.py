"""Reset a workspace to a blank state for a fresh evaluation.

Clears everything a run produces or remembers -- hunts, research, Sigma rules,
LangGraph checkpoints, quota and run state, CTI cursors, parked and processed
CTI, pending query proposals, and logs -- after archiving it all to one
tarball. Configuration (.env, .hecateconfig.yaml), knowledge, templates and
the hunts/ README and format guide are left alone.

The ID counters are not zeroed. Each is set to the highest ID that git history
under hunts/ or research/ has ever held, so the next draft starts one past it
and never reuses an ID an earlier, unrelated hunt carried. IDs that were
allocated but never committed are free to hand out again.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from hecate_agent.core.hunt_ids import hunt_id_lock

from hecate_runner.config import Settings
from hecate_runner.parked_store import parked_dir

#: LangGraph's SqliteSaver writes this relative to whatever directory the
#: `hecate-agent orchestrate` command was run from.
CHECKPOINT_DB = "hecate_checkpoints.sqlite"
_SQLITE_SIDECARS = ("", "-wal", "-shm")
_GIT_TIMEOUT_SEC = 30


@dataclass
class ResetPlan:
    workspace: Path
    #: Group name -> paths that exist and will be archived, then removed.
    groups: dict[str, list[Path]] = field(default_factory=dict)
    hunt_counter: int = 0
    research_counter: int = 0
    git_repo: bool = False

    @property
    def paths(self) -> list[Path]:
        return [p for group in self.groups.values() for p in group]


def _existing(paths: list[Path]) -> list[Path]:
    seen: list[Path] = []
    for path in paths:
        if path.exists() and path not in seen:
            seen.append(path)
    return seen


def _is_git_repo(workspace: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def max_id_in_git(workspace: Path, subdir: str, prefix: str) -> int:
    """Highest ``<prefix>NNNN.md`` ever committed under ``subdir``, or 0."""
    try:
        proc = subprocess.run(
            ["git", "log", "--all", "--pretty=format:", "--name-only", "--", subdir],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    if proc.returncode != 0:
        return 0
    return max(
        (int(m) for m in re.findall(rf"{re.escape(prefix)}(\d+)\.md", proc.stdout)), default=0
    )


def _cursor_files(settings: Settings) -> list[Path]:
    """Every CTI cursor the providers keep, plus backups written beside them."""
    ws = settings.hecate_workspace
    cursors = [
        settings.otx_cursor_file,
        settings.rss_cursor_file,
        settings.misp_cursor_file,
        settings.multi_cursor_file,
        ws / ".cursors",  # abuse.ch and CISA KEV
    ]
    for cursor in list(cursors):
        if cursor.suffix == ".json":
            cursors.extend(sorted(cursor.parent.glob(f"{cursor.name}.*")))
    return cursors


def build_plan(
    settings: Settings, *, keep_cursors: bool = False, cwd: Path | None = None
) -> ResetPlan:
    ws = settings.hecate_workspace
    queue = settings.cti_queue_dir_resolved
    checkpoint_dirs = [ws, ws.parent, cwd or Path.cwd()]
    plan = ResetPlan(workspace=ws, git_repo=_is_git_repo(ws))
    plan.groups = {
        "hunts": sorted((ws / "hunts").rglob("H-*.md")),
        "research": sorted((ws / "research").glob("R-*.md")),
        "sigma rules": sorted((ws / "queries").glob("H-*")),
        "graph checkpoints": _existing(
            [d / f"{CHECKPOINT_DB}{s}" for d in checkpoint_dirs for s in _SQLITE_SIDECARS]
        ),
        "run state and quota": _existing([settings.state_file, settings.pending_queries_dir]),
        "CTI cursors": [] if keep_cursors else _existing(_cursor_files(settings)),
        "CTI queue": _existing([parked_dir(queue), queue / "processed", settings.cti_next_file]),
        "logs": sorted(
            [
                *settings.log_dir.glob(f"{settings.log_file.name}*"),
                *settings.log_dir.glob(f"{settings.metrics_file.name}*"),
                *settings.log_dir.glob(f"{settings.llm_calls_file.name}*"),
            ]
        ),
    }
    if plan.git_repo:
        plan.hunt_counter = max_id_in_git(ws, "hunts", "H-")
        plan.research_counter = max_id_in_git(ws, "research", "R-")
    return plan


def running_hecate_processes() -> list[str]:
    """Command lines of other live hecate-agent / hecate-runner processes.

    Matched on argv rather than a pattern over the whole command line, so a
    shell whose command merely mentions the names is not mistaken for one.
    """
    own = {os.getpid(), os.getppid()}
    found: list[str] = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) in own:
            continue
        try:
            argv = (proc / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        names = [Path(a.decode(errors="replace")).name for a in argv[:2] if a]
        if any(n in ("hecate-agent", "hecate-runner", "hecate-agent-mcp") for n in names):
            found.append(f"{proc.name}: {b' '.join(argv).decode(errors='replace').strip()}")
    return found


def archive(plan: ResetPlan, archive_dir: Path) -> Path:
    """Tar everything the reset will remove, owner-only; return the tarball path."""
    archive_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = archive_dir / f"hecate-reset-archive-{stamp}.tar.gz"
    with tarfile.open(target, "w:gz") as tar:
        for path in plan.paths:
            try:
                arcname = str(path.relative_to(plan.workspace.parent))
            except ValueError:
                arcname = str(path).lstrip("/")
            tar.add(path, arcname=arcname)
    target.chmod(0o600)
    return target


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def execute(plan: ResetPlan, settings: Settings) -> None:
    """Remove the planned paths and write the counters. Archive first."""
    ws = plan.workspace
    with hunt_id_lock(ws / "hunts"):
        if plan.git_repo:
            # Staged copies would otherwise survive the delete: a commit after
            # the reset re-adds a hunt that is no longer on disk.
            subprocess.run(
                ["git", "reset", "-q", "--", "hunts", "research", "queries"],
                cwd=ws,
                capture_output=True,
                timeout=_GIT_TIMEOUT_SEC,
                check=False,
            )
        for path in plan.paths:
            _remove(path)
        for quarter in sorted((ws / "hunts").glob("*/*"), reverse=True):
            if quarter.is_dir() and not any(quarter.iterdir()):
                quarter.rmdir()
        for year in (ws / "hunts").glob("*"):
            if year.is_dir() and year.name.isdigit() and not any(year.iterdir()):
                year.rmdir()
        for directory in (ws / "research", ws / "queries", settings.log_dir):
            directory.mkdir(parents=True, exist_ok=True)
        # The service appends to this path with systemd's StandardOutput=append:,
        # which creates a missing file as root; recreating it here keeps it
        # owned by whoever runs the Runner.
        settings.log_file.touch()
        settings.cti_queue_dir_resolved.mkdir(parents=True, exist_ok=True)
        (ws / "hunts" / ".hunt_id_counter").write_text(f"{plan.hunt_counter}\n")
        (ws / "research" / ".research_id_counter").write_text(
            json.dumps({"R-": plan.research_counter}, indent=2, sort_keys=True)
        )
