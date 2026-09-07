"""Size-based rotation for a log file that has two independent writers.

``logging.handlers.RotatingFileHandler`` is the obvious tool here and is the
wrong one. It rotates by *renaming* the live file, which is only safe when the
rotating process is the sole writer. This log is not:

    StandardOutput=append:/…/logs/orchestrator.log
    StandardError=append:/…/logs/orchestrator.log

systemd opens that file itself when the unit starts and holds the descriptor
for the life of the run. A rename moves the inode out from under it, so
everything systemd writes for the rest of that run lands in the archive while
Python writes to the new file -- output split across two files with no error.

So this rotates the way logrotate's ``copytruncate`` does: copy the contents
aside, then truncate the original **in place**, keeping the inode. Both
writers' descriptors stay valid and simply continue at the start of the
now-empty file. Both open with ``O_APPEND`` (systemd's ``append:`` and
logging's mode ``"a"``), so neither leaves a sparse gap after the truncation.

The trade-off copytruncate always carries: anything written between the copy
and the truncate is lost. That window is microseconds, and it is bounded to a
rotation that happens once per several thousand hourly runs.
"""

from __future__ import annotations

import fcntl
import logging
import os
import shutil
from contextlib import contextmanager
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger(__name__)

_LOCK_SUFFIX = ".rotate.lock"


@contextmanager
def _rotation_lock(path: Path) -> Iterator[None]:
    """Serialise rotation across processes.

    Overlapping runs are real here -- a manual `hecate-runner run` while the
    hourly timer fires -- and two processes rotating at once would produce a
    duplicated archive and lose a slice of the log between them.
    """
    lock_path = path.with_name(path.name + _LOCK_SUFFIX)
    with open(lock_path, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def rotate_log_if_needed(path: Path, *, max_bytes: int, backup_count: int) -> bool:
    """Rotate ``path`` when it exceeds ``max_bytes``. Returns True if it did.

    Archives are ``<name>.1`` (newest) through ``<name>.<backup_count>``;
    anything older is discarded. ``backup_count`` of 0 truncates without
    keeping any history.

    Never raises: a log that cannot be rotated is a much smaller problem than
    a cycle that dies because of it, and the caller is about to do real work.
    """
    if max_bytes <= 0:
        return False

    try:
        if not path.exists() or path.stat().st_size <= max_bytes:
            return False
    except OSError:
        return False

    try:
        with _rotation_lock(path):
            # Re-check under the lock: another process may have just rotated,
            # in which case the file is small again and there is nothing to do.
            if not path.exists() or path.stat().st_size <= max_bytes:
                return False

            for index in range(backup_count, 0, -1):
                source = path.with_name(f"{path.name}.{index}")
                if not source.exists():
                    continue
                if index == backup_count:
                    source.unlink()
                else:
                    source.replace(path.with_name(f"{path.name}.{index + 1}"))

            if backup_count > 0:
                shutil.copy2(path, path.with_name(f"{path.name}.1"))

            # Truncate rather than replace: see the module docstring.
            os.truncate(path, 0)
    except OSError as exc:
        log.warning("Could not rotate %s (%s); continuing with the existing file.", path, exc)
        return False

    return True
