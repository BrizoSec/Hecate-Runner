"""Per-run state persistence — currently just tracks the daily draft quota."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class OrchestratorState:
    """Small on-disk struct so daily quota survives across systemd runs."""

    date: str = ""
    drafts_today: int = 0
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
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2))

    # --- Behaviors ---------------------------------------------------------

    def check_and_reserve_draft(self, max_per_day: int) -> bool:
        """Return True if we're under quota (and consume one), False if capped."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if self.date != today:
            self.date = today
            self.drafts_today = 0

        if self.drafts_today >= max_per_day:
            return False

        self.drafts_today += 1
        self.total_drafts_ever += 1
        return True

    def mark_run(self, *, success: bool) -> None:
        self.last_run_iso = datetime.now(UTC).isoformat()
        if success:
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
