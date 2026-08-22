"""File-queue CTI provider.

Reads ``<cti_queue>/next.txt`` if present, archives it to
``<cti_queue>/processed/cti-<timestamp>.txt`` after successful use.

Simple, transparent, and easy to feed either by hand or from other tooling
that writes into the queue.
"""

from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)


class FileQueueProvider(CTIProvider):
    """Read CTI from a plain text file, archive after ack."""

    name = "file"

    def __init__(self, queue_dir: Path):
        self.queue_dir = queue_dir
        self.next_file = queue_dir / "next.txt"
        self.processed_dir = queue_dir / "processed"

    def next_item(self) -> CTIItem | None:
        if not self.next_file.exists():
            log.debug("No CTI at %s", self.next_file)
            return None

        content = self.next_file.read_text().strip()
        if not content:
            log.debug("CTI file %s empty", self.next_file)
            return None

        return CTIItem(
            content=content,
            source=self.name,
            received_at=datetime.now(UTC),
            identifier=self.next_file.name,
        )

    def acknowledge(self, item: CTIItem) -> None:
        if not self.next_file.exists():
            return
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        stamp = (item.received_at or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
        archive = self.processed_dir / f"cti-{stamp}.txt"
        shutil.move(str(self.next_file), str(archive))
        log.info("Archived CTI to %s", archive)

    def ensure_dirs(self) -> None:
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
