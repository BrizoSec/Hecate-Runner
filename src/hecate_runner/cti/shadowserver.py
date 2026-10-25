"""Shadowserver Foundation infrastructure & threat intelligence CTI provider.

Ingests active malware command-and-control (C2) sinkhole connections, botnet infections,
and exposed perimeter vulnerabilities cataloged by The Shadowserver Foundation
(https://www.shadowserver.org).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)


class ShadowserverError(RuntimeError):
    """Raised when an operation on the Shadowserver provider fails."""


@dataclass
class ShadowserverCursorState:
    """Track processed Shadowserver infection event identifiers."""

    seen_ids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> ShadowserverCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_ids=list(data.get("seen_ids", [])))
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            log.warning("Shadowserver cursor %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps({"seen_ids": self.seen_ids[-1000:]}, indent=2))

    def already_seen(self, event_id: str) -> bool:
        return event_id in self.seen_ids

    def advance(self, event_id: str) -> None:
        if event_id and event_id not in self.seen_ids:
            self.seen_ids.append(event_id)


class ShadowserverProvider(CTIProvider):
    """CTI provider consuming active infection and C2 telemetry from Shadowserver."""

    name: str = "shadowserver"

    def __init__(
        self,
        cursor_file: Path,
        api_key: str | None = None,
        api_secret: str | None = None,
        base_url: str = "https://transform.shadowserver.org/api2",
        request_timeout_sec: float = 20.0,
        client: httpx.Client | None = None,
    ):
        self.cursor_file = cursor_file
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url.rstrip("/")
        self.request_timeout_sec = request_timeout_sec
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={"User-Agent": "Hecate-Runner/1.0", "Accept": "application/json"},
            follow_redirects=True,
        )
        self._owns_client = client is None
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def next_item(self) -> CTIItem | None:
        if not (self.api_key and self.api_secret):
            log.debug("Shadowserver provider skipped: SHADOWSERVER_API_KEY/SECRET not configured")
            return None

        cursor = ShadowserverCursorState.load(self.cursor_file)
        try:
            events = self._fetch_recent_events()
        except ShadowserverError as exc:
            log.warning("Failed to query Shadowserver API: %s", exc)
            return None

        for event in events:
            event_id = str(
                event.get("id") or f"{event.get('ip')}:{event.get('port')}-{event.get('tag')}"
            ).strip()
            if not event_id or cursor.already_seen(event_id):
                continue

            return self._event_to_cti_item(event_id, event)

        log.debug("No new unrouted Shadowserver infrastructure events")
        return None

    def acknowledge(self, item: CTIItem) -> None:
        event_id = item.metadata.get("event_id") or item.identifier
        if not event_id:
            log.warning("Cannot acknowledge Shadowserver item without event_id (%r)", item)
            return
        cursor = ShadowserverCursorState.load(self.cursor_file)
        cursor.advance(str(event_id))
        cursor.save(self.cursor_file)

    def _fetch_recent_events(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/reports/list"
        payload = {"apikey": self.api_key, "secret": self.api_secret}
        try:
            resp = self._client.post(url, json=payload)
        except httpx.RequestError as exc:
            raise ShadowserverError(f"HTTP request to {url} failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise ShadowserverError(
                f"Authentication failure (HTTP {resp.status_code}); check credentials"
            )
        if resp.status_code == 429:
            raise ShadowserverError("Shadowserver API rate limit reached")
        if resp.status_code != 200:
            raise ShadowserverError(f"HTTP {resp.status_code} from {url}")

        data = resp.json()
        if isinstance(data, list):
            return list(data)
        return list(data.get("reports") or data.get("data") or [])

    def _event_to_cti_item(self, event_id: str, event: dict[str, Any]) -> CTIItem:
        ip = str(event.get("ip") or event.get("dst_ip") or "0.0.0.0").strip()
        port = str(event.get("port") or event.get("dst_port") or "443").strip()
        tag = str(event.get("tag") or event.get("type") or "C2-Sinkhole").strip()
        family = str(event.get("family") or event.get("malware") or tag).strip()
        asn = str(event.get("asn") or "")
        asn_name = str(event.get("asn_name") or "Unknown AS")
        city = str(event.get("city") or "")
        country = str(event.get("country") or "Unknown")

        techniques = ["T1071.001", "T1571"]
        if "exploit" in tag.lower() or "vulnerable" in tag.lower():
            techniques.append("T1190")

        title = f"Shadowserver Threat Infrastructure: {family} ({ip}:{port})"
        link = "https://www.shadowserver.org"

        lines = [
            f"Shadowserver Threat Infrastructure: {family}",
            "Source: The Shadowserver Foundation",
            f"Adversary / Infected Host: {ip}",
            f"Port: {port}",
            f"Infection / Activity Tag: {tag}",
            f"Origin: AS{asn} ({asn_name}) in {city}, {country}".replace(" in ,", " in"),
            f"{ATTACK_TECHNIQUE_LINE} {', '.join(sorted(techniques))}",
            "\nObservation Details:",
            f"Active adversary communication or honeypot probe observed targeting {ip}:{port}.",
            "Ground truth telemetry provided by Shadowserver global sensor and sinkhole network.",
        ]

        content = "\n".join(lines)

        metadata = {
            "event_id": event_id,
            "ip": ip,
            "port": port,
            "family": family,
            "tag": tag,
            "asn": asn,
            "techniques": sorted(techniques),
            "indicators": {"ipv4": [ip]},
            "evidence_profile": "infrastructure_telemetry",
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=datetime.now(UTC),
            identifier=event_id,
            metadata=metadata,
            title=title,
            source_url=link,
        )
