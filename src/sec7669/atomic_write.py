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


def atomic_write_text(path: Path, content: str) -> None:
    """Write `content` to `path` atomically (write to a temp file in the same
    directory, then rename over the destination)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise
