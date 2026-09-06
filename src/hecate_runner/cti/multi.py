"""Composite CTI provider that fans out across multiple configured sources.

Wraps N ``CTIProvider`` instances (e.g. rss + otx + misp) behind the same
single-provider interface the orchestrator already knows, so
``Orchestrator`` never has to know it's talking to more than one source.

Which provider gets first pick each cycle is round-robined and persisted to
disk: a consistently high-volume source (e.g. RSS across ten feeds) would
otherwise crowd out a slower one (e.g. MISP with few new events) purely by
always being checked first. A source is only skipped in a given cycle if it
genuinely has nothing new — the rotation just decides tie-break order, not
which sources are eligible.

A single sub-provider raising is isolated (logged, skipped) rather than
sinking the whole cycle, mirroring how ``RssProvider`` already isolates a
single broken feed from the others.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)


class MultiProviderError(RuntimeError):
    """Raised when the multi CTI provider is misconfigured."""


@dataclass
class MultiCursorState:
    """Persisted index of which sub-provider gets first pick next cycle."""

    next_index: int = 0

    @classmethod
    def load(cls, path: Path) -> MultiCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(next_index=int(data.get("next_index", 0)))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            log.warning("Multi CTI cursor file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps({"next_index": self.next_index}))


class MultiProvider(CTIProvider):
    """Fans out ``next_item``/``acknowledge`` across multiple sub-providers."""

    name = "multi"

    def __init__(self, providers: list[CTIProvider], cursor_file: Path):
        if not providers:
            raise MultiProviderError(
                "At least one sub-provider is required to use the multi CTI provider"
            )
        names = [p.name for p in providers]
        if len(set(names)) != len(names):
            raise MultiProviderError(
                f"Duplicate provider names passed to multi CTI provider: {names}"
            )
        self.providers = providers
        self.cursor_file = cursor_file
        self._by_name = {p.name: p for p in providers}

    # --- CTIProvider interface -----------------------------------------------

    def next_item(self) -> CTIItem | None:
        cursor = MultiCursorState.load(self.cursor_file)
        count = len(self.providers)
        start = cursor.next_index % count

        for offset in range(count):
            idx = (start + offset) % count
            provider = self.providers[idx]
            try:
                item = provider.next_item()
            except Exception as exc:  # one bad source shouldn't sink the cycle
                log.warning(
                    "CTI sub-provider %r failed (%s); trying the next configured source",
                    provider.name,
                    exc,
                )
                continue
            if item is not None:
                cursor.next_index = (idx + 1) % count
                cursor.save(self.cursor_file)
                log.info(
                    "Multi CTI: picked %s (next cycle starts at %s)",
                    provider.name,
                    self.providers[cursor.next_index].name,
                )
                return item

        log.debug("No new entries across %d configured CTI sources", count)
        return None

    def acknowledge(self, item: CTIItem) -> None:
        provider = self._by_name.get(item.source)
        if provider is None:
            log.warning(
                "Cannot acknowledge CTI item: unknown source %r (known: %s)",
                item.source,
                list(self._by_name),
            )
            return
        provider.acknowledge(item)
