"""A readable account of one orchestrator cycle: what it decided, and why.

The module loggers record events ("Research R-0007 is ready as background
context"); they do not say what the cycle was looking at or which branch it
took. This logger does, one line per decision, all tagged with the same short
cycle ID so a run can be followed with ``hecate-runner watch`` or::

    grep 'hecate_runner.trail' logs/orchestrator.log

A line reads ``[c7f3a1 +  84.2s] research   R-0012 done in 81s; ...``: the
cycle, seconds since it started, the stage, and the decision.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

LOGGER_NAME = "hecate_runner.trail"

_log = logging.getLogger(LOGGER_NAME)


class CycleTrail:
    """Stage-by-stage log lines for one cycle, sharing an ID and a clock."""

    def __init__(self) -> None:
        self.cycle_id = uuid.uuid4().hex[:6]
        self._start = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def step(self, stage: str, message: str, *args: Any) -> None:
        _log.info("[%s +%6.1fs] %-10s " + message, self.cycle_id, self.elapsed, stage, *args)


def listing(values: Iterable[Any], empty: str = "none") -> str:
    """``a, b, c`` -- or ``empty`` -- for a trail line."""
    rendered = ", ".join(str(v) for v in values)
    return rendered or empty


def counts(inventory: Mapping[str, Any]) -> str:
    """``IPv4 4, domain 1`` for an indicator map of type -> values."""
    return listing(
        f"{kind} {len(v) if isinstance(v, (list, tuple)) else v}" for kind, v in inventory.items()
    )


def clip(text: str, limit: int = 110) -> str:
    """One line of ``text``, shortened for a log line."""
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
