from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

THREATFOX_RECENT_URL = "https://threatfox.abuse.ch/export/json/recent/"

@dataclass
class AbuseChCursorState:
    last_id: int = 0

    def to_json(self) -> str:
        return json.dumps({"last_id": self.last_id})

    @classmethod
    def from_file(cls, path: Path) -> AbuseChCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(last_id=data.get("last_id", 0))
        except (OSError, ValueError):
            return cls()


class AbuseChProvider(CTIProvider):
    """Abuse.ch ThreatFox CTI provider.

    Polls the ThreatFox recent JSON export for new indicators. Since ThreatFox
    indicators lack behavioral narrative, they feed directly into the
    indicator sweep pipeline.
    """

    name = "abuse_ch"

    def __init__(self, cursor_file: Path) -> None:
        self.cursor_file = cursor_file
        self._items: list[CTIItem] = []
        self._fetched = False

    def _map_ioc_type(self, tf_type: str) -> str:
        mapping = {
            "ip:port": "ip-dst|port",
            "domain": "domain",
            "url": "url",
            "sha256_hash": "sha256",
            "md5_hash": "md5",
        }
        return mapping.get(tf_type, tf_type)

    def _fetch_recent(self) -> None:
        if self._fetched:
            return
            
        cursor = AbuseChCursorState.from_file(self.cursor_file)
        
        try:
            response = httpx.get(THREATFOX_RECENT_URL, timeout=15.0)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            log.warning("Failed to fetch ThreatFox recent JSON: %s", e)
            self._fetched = True
            return

        # Sort items by ID ascending
        # data keys are strings representing IDs
        valid_items = []
        for id_str, entries in data.items():
            if not id_str.isdigit():
                continue
            item_id = int(id_str)
            if item_id > cursor.last_id and entries:
                valid_items.append((item_id, entries[0]))
                
        valid_items.sort(key=lambda x: x[0])
        
        for item_id, entry in valid_items:
            ioc_value = entry.get("ioc_value", "")
            ioc_type = entry.get("ioc_type", "")
            malware = entry.get("malware_printable") or entry.get("malware") or "Unknown"
            
            mapped_type = self._map_ioc_type(ioc_type)
            
            # Construct a blurb that triggers the indicator sweep
            blurb = f"ThreatFox Indicator: {malware}\n"
            blurb += f"Indicators (1 total): {mapped_type} (1)\n\n"
            blurb += f"Malware: {malware}\n"
            blurb += f"IOC: {ioc_value} ({ioc_type})\n"
            
            self._items.append(
                CTIItem(
                    content=blurb,
                    source="abuse_ch",
                    identifier=str(item_id),
                    title=f"ThreatFox Indicator: {malware}",
                    source_url=f"https://threatfox.abuse.ch/ioc/{item_id}/",
                )
            )
            
        self._fetched = True

    def next_item(self) -> CTIItem | None:
        self._fetch_recent()
        if not self._items:
            return None
        return self._items[0]

    def acknowledge(self, item: CTIItem) -> None:
        if not self._items or self._items[0].identifier != item.identifier:
            return
            
        self._items.pop(0)
        cursor = AbuseChCursorState.from_file(self.cursor_file)
        item_id = int(item.identifier)
        if item_id > cursor.last_id:
            cursor.last_id = item_id
            
        atomic_write_text(self.cursor_file, cursor.to_json())
