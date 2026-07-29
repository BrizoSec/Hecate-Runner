"""Persistence for proposed queries awaiting human approval.

One JSON file per hunt_id under a directory -- same directory-of-files
pattern as cti/file_queue.py, chosen for the same reasons: easy to inspect
or hand-edit, no single-file lock contention across unrelated hunts.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from sec7669.atomic_write import atomic_write_text
from sec7669.query_execution import ProposedQuery

log = logging.getLogger(__name__)


class PendingQueryStore:
    def __init__(self, store_dir: Path):
        self.store_dir = store_dir

    def _path(self, hunt_id: str) -> Path:
        return self.store_dir / f"{hunt_id}.json"

    def save(self, query: ProposedQuery) -> Path:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        path = self._path(query.hunt_id)
        atomic_write_text(path, json.dumps(query.to_dict(), indent=2))
        log.info("Staged proposed query for %s at %s", query.hunt_id, path)
        return path

    def load(self, hunt_id: str) -> ProposedQuery | None:
        path = self._path(hunt_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            log.warning("Pending query file %s is corrupt (%s)", path, exc)
            return None
        return ProposedQuery.from_dict(data)

    def remove(self, hunt_id: str) -> None:
        path = self._path(hunt_id)
        if path.exists():
            path.unlink()

    def list_all(self) -> list[ProposedQuery]:
        if not self.store_dir.exists():
            return []
        queries = []
        for path in sorted(self.store_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text())
                queries.append(ProposedQuery.from_dict(data))
            except json.JSONDecodeError:
                log.warning("Skipping corrupt pending query file %s", path)
        return queries
