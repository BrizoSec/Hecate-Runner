from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_RECENT_URL = "https://threatfox.abuse.ch/export/json/recent/"


@dataclass
class AbuseChCursorState:
    last_id: int = 0

    def to_json(self) -> str:
        return json.dumps({"last_id": self.last_id})

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path, self.to_json())

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

    Polls the ThreatFox API / JSON export for new indicators. Since ThreatFox
    indicators lack behavioral narrative, they feed directly into the
    indicator sweep pipeline.
    """

    name = "abuse_ch"

    def __init__(
        self,
        cursor_file: Path,
        *,
        api_key: str | None = None,
        api_url: str = THREATFOX_API_URL,
        request_timeout_sec: float = 15.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.api_key = api_key
        self.api_url = api_url
        self.request_timeout_sec = request_timeout_sec
        self._external_client = client is not None
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={
                "User-Agent": "Hecate-Runner/1.0",
                "Accept": "application/json",
                **({"Auth-Key": api_key} if api_key else {}),
            },
            follow_redirects=True,
        )
        self._items: list[CTIItem] = []
        self._fetched = False
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def _map_ioc_type(self, tf_type: str) -> str:
        mapping = {
            "ip:port": "ipv4",
            "ip": "ipv4",
            "domain": "domain",
            "url": "url",
            "sha256_hash": "sha256",
            "sha256": "sha256",
            "md5_hash": "md5",
            "md5": "md5",
        }
        return mapping.get(tf_type.lower().strip(), "other")

    def _fetch_recent(self) -> None:
        if self._fetched:
            return

        cursor = AbuseChCursorState.from_file(self.cursor_file)

        raw_entries: list[dict[str, Any]] = []
        # Mode 1: Authenticated API endpoint (modern ThreatFox API v1)
        try:
            payload = {"query": "get_iocs", "days": 1}
            headers = {"User-Agent": "Hecate-Runner/1.0", "Accept": "application/json"}
            if self.api_key:
                headers["Auth-Key"] = self.api_key
            resp = self._client.post(self.api_url, json=payload, headers=headers)
            if resp.status_code == 200:
                body = resp.json()
                if body.get("query_status") == "ok":
                    raw_entries = body.get("data") or []
        except Exception as exc:
            log.debug("ThreatFox API v1 query omitted (%s)", exc)

        # Mode 2: Legacy unauthenticated JSON export fallback (for backwards compatibility/mock)
        if not raw_entries:
            try:
                resp = self._client.get(THREATFOX_RECENT_URL)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        for id_str, entries in data.items():
                            if id_str.isdigit() and entries:
                                entry = entries[0] if isinstance(entries, list) else entries
                                if "id" not in entry:
                                    entry["id"] = int(id_str)
                                raw_entries.append(entry)
                    elif isinstance(data, list):
                        raw_entries = data
            except Exception as exc:
                log.warning("Failed to fetch ThreatFox indicators: %s", exc)
                self._fetched = True
                return

        valid_items: list[tuple[int, dict[str, Any]]] = []
        for entry in raw_entries:
            try:
                item_id = int(entry.get("id") or 0)
            except (ValueError, TypeError):
                continue
            if item_id > cursor.last_id:
                valid_items.append((item_id, entry))

        valid_items.sort(key=lambda x: x[0])

        for item_id, entry in valid_items:
            ioc_value = str(entry.get("ioc") or entry.get("ioc_value") or "").strip()
            if not ioc_value:
                continue
            ioc_type = str(entry.get("ioc_type") or "").strip()
            malware = str(
                entry.get("malware_printable") or entry.get("malware") or "Unknown"
            ).strip()
            threat_type = str(
                entry.get("threat_type_desc") or entry.get("threat_type") or "Threat Indicator"
            ).strip()

            mapped_type = self._map_ioc_type(ioc_type)

            blurb = (
                f"ThreatFox Indicator: {malware}\n"
                f"Indicators (1 total): {mapped_type} (1)\n\n"
                f"Malware: {malware}\n"
                f"Threat Type: {threat_type}\n"
                f"IOC: {ioc_value} ({ioc_type})\n"
            )

            clean_val = (
                ioc_value.split(":")[0] if mapped_type == "ipv4" and ":" in ioc_value else ioc_value
            )
            self._items.append(
                CTIItem(
                    content=blurb,
                    source=self.name,
                    identifier=str(item_id),
                    title=f"ThreatFox Indicator: {malware}",
                    source_url=f"https://threatfox.abuse.ch/ioc/{item_id}/",
                    metadata={
                        "indicator_only": True,
                        "ioc_value": ioc_value,
                        "ioc_type": ioc_type,
                        "malware": malware,
                        "threat_type": threat_type,
                        "indicators": {mapped_type: [clean_val]},
                    },
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

        cursor.save(self.cursor_file)
