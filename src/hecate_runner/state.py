"""Per-run state persistence — tracks the daily draft and research quotas."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.atomic_write import atomic_write_text

log = logging.getLogger(__name__)


@dataclass
class OrchestratorState:
    """Small on-disk struct so daily quota survives across systemd runs."""

    date: str = ""
    drafts_today: int = 0
    research_runs_today: int = 0
    total_drafts_ever: int = 0
    last_run_iso: str = ""
    consecutive_failures: int = 0
    extras: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> OrchestratorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("state file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps(asdict(self), indent=2))

    # --- Behaviors ---------------------------------------------------------

    def check_and_reserve_draft(self, max_per_day: int) -> bool:
        """Return True if we're under quota (and consume one), False if capped."""
        self._roll_day()
        if self.drafts_today >= max_per_day:
            return False

        self.drafts_today += 1
        self.total_drafts_ever += 1
        return True

    def check_and_reserve_research(self, max_per_day: int) -> bool:
        """Return True if a web-searching research run is under quota (and consume one).

        Kept separate from the draft quota on purpose: a draft reservation is
        refunded when a cycle fails after research, but the search credits that
        research spent are not, so the retry would otherwise search again
        without limit.
        """
        self._roll_day()
        if self.research_runs_today >= max_per_day:
            return False
        self.research_runs_today += 1
        return True

    def _roll_day(self) -> None:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if self.date != today:
            self.date = today
            self.drafts_today = 0
            self.research_runs_today = 0

    def mark_run(self, *, success: bool) -> None:
        self.last_run_iso = datetime.now(UTC).isoformat()
        if success:
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
