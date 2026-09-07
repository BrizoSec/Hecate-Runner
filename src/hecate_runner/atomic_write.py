"""Shared atomic-write helper for the small JSON state files this project
persists (orchestrator quota state, CTI cursor state, pending queries).

Plain `path.write_text(...)` writes in place -- if the process is killed
mid-write (systemd's `TimeoutStartSec=900` sends SIGKILL on timeout, and any
of these files could be mid-write at that moment), the file is left
truncated or partially overwritten. Most of these files already tolerate
that via a JSONDecodeError-triggers-a-reset fallback, but a reset silently
loses real state (the day's draft count, a CTI cursor position, a pending
query) rather than failing loudly -- write-to-temp-then-rename avoids the
corruption case entirely: `os.replace` is atomic on POSIX, so a reader only
ever sees the old complete file or the new complete file, never a partial
one.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def default_file_mode() -> int:
    """Mode a plain open() would create: 0o666 masked by the process umask.

    mkstemp() hardcodes 0o600 and os.replace carries that mode onto the
    destination, so a file written through this helper ends up private to
    its owner rather than matching the 0o644 a plain write_text() produces
    under the service's umask. Callers that want ordinary file permissions
    pass this as `mode`.

    Read once at import, before any worker threads exist -- querying the
    umask means temporarily setting it, which is not thread-safe.
    """
    umask = os.umask(0o022)
    os.umask(umask)
    return 0o666 & ~umask


DEFAULT_FILE_MODE = default_file_mode()


def atomic_write_text(path: Path, content: str, mode: int | None = None) -> None:
    """Write `content` to `path` atomically (write to a temp file in the same
    directory, then rename over the destination).

    `mode` is applied to the temp file before the rename. It defaults to None,
    which keeps mkstemp's restrictive 0o600 -- existing callers' permissions
    are deliberately left alone; pass DEFAULT_FILE_MODE for a file that should
    look like any other file in the workspace.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        if mode is not None:
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
