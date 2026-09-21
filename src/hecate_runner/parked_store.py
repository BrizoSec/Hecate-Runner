"""Durable holding area for CTI the triage gate declined to draft from.

Parking exists so the intake gate never has to be right. A dropped item is
invisible and permanent -- the cursor advances past it and nothing records
the loss -- whereas a parked one is a file on disk with the reason attached,
listable and restorable. That is what makes it acceptable to gate on a
heuristic at all.

Items are stored whole, not as a reference: the provider cursor has already
moved on by the time anything is parked, so the copy here is the only one
left.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti import CTIItem

log = logging.getLogger(__name__)

_DIR_NAME = "parked"


@dataclass
class ParkedItem:
    """A CTI item held back, with everything needed to replay it."""

    park_id: str
    parked_at: str
    source: str
    title: str
    reason: str
    content: str
    source_url: str = ""
    identifier: str = ""
    path: Path | None = None


def parked_dir(queue_dir: Path) -> Path:
    return queue_dir / _DIR_NAME


def _park_id(item: CTIItem, when: datetime) -> str:
    seed = item.identifier or item.source_url or item.title or item.content[:200]
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    return f"{when.strftime('%Y%m%dT%H%M%SZ')}-{digest}"


def park(queue_dir: Path, item: CTIItem, reason: str) -> Path:
    """Write one item to the parked area and return its path."""
    when = datetime.now(UTC)
    park_id = _park_id(item, when)
    target = parked_dir(queue_dir)
    target.mkdir(parents=True, exist_ok=True)
    payload = {
        "park_id": park_id,
        "parked_at": when.isoformat(),
        "source": item.source,
        "title": item.title,
        "source_url": item.source_url,
        "identifier": item.identifier,
        "reason": reason,
        "content": item.content,
    }
    path = target / f"{park_id}.json"
    atomic_write_text(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    log.info("Parked CTI item %s (%s)", park_id, reason)
    return path


def _read(path: Path) -> ParkedItem | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("Could not read parked item %s", path)
        return None
    return ParkedItem(
        park_id=str(raw.get("park_id") or path.stem),
        parked_at=str(raw.get("parked_at") or ""),
        source=str(raw.get("source") or ""),
        title=str(raw.get("title") or ""),
        reason=str(raw.get("reason") or ""),
        content=str(raw.get("content") or ""),
        source_url=str(raw.get("source_url") or ""),
        identifier=str(raw.get("identifier") or ""),
        path=path,
    )


def list_parked(queue_dir: Path) -> list[ParkedItem]:
    """Every parked item, newest first."""
    target = parked_dir(queue_dir)
    if not target.is_dir():
        return []
    items = [found for path in sorted(target.glob("*.json")) if (found := _read(path))]
    return sorted(items, key=lambda i: i.parked_at, reverse=True)


def get_parked(queue_dir: Path, park_id: str) -> ParkedItem | None:
    """One parked item by id, or by any unambiguous fragment of one.

    Matching is on a substring rather than a prefix because the memorable
    half of an id is the hash on the end -- ``20260909T023320Z-d5f26abd`` --
    and that is what gets copied out of the listing. An ambiguous fragment
    resolves to nothing rather than to an arbitrary one of its matches:
    restoring the wrong item is worse than being asked to be specific.
    """
    if not park_id:
        return None
    exact = parked_dir(queue_dir) / f"{park_id}.json"
    if exact.exists():
        return _read(exact)
    matches = [item for item in list_parked(queue_dir) if park_id in item.park_id]
    return matches[0] if len(matches) == 1 else None


def restore(queue_dir: Path, item: ParkedItem) -> Path:
    """Put a parked item back on the file queue and drop it from the park.

    The file queue holds one item, so a restore overwrites whatever is
    already staged there; callers check first.
    """
    next_file = queue_dir / "next.txt"
    queue_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_text(next_file, item.content.rstrip("\n") + "\n")
    if item.path is not None:
        item.path.unlink(missing_ok=True)
    log.info("Restored parked item %s to %s", item.park_id, next_file)
    return next_file


def prune_parked(queue_dir: Path, max_age_days: int) -> int:
    """Delete parked items older than max_age_days."""
    if max_age_days <= 0:
        return 0
    now = datetime.now(UTC)
    count = 0
    for item in list_parked(queue_dir):
        try:
            item_time = datetime.fromisoformat(item.parked_at)
            if (now - item_time).days > max_age_days and item.path and item.path.exists():
                item.path.unlink()
                count += 1
        except Exception as e:
            log.warning(f"Failed to check/prune parked item {item.park_id}: {e}")
    if count > 0:
        log.info(f"Pruned {count} parked items older than {max_age_days} days.")
    return count
