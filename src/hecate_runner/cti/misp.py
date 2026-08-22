"""MISP (Malware Information Sharing Platform) CTI provider.

Polls ``POST /events/restSearch`` for events modified since a persisted
cursor, filters for high-signal events (published, not TLP:RED/AMBER), and
returns the oldest unrouted candidate as a ``CTIItem``.

Field shapes below were verified against MISP's own bundled test fixture
(``/var/www/MISP/tests/event.json`` inside the misp-core container) and its
ATT&CK galaxy cluster library (``app/files/misp-galaxy/clusters/
mitre-attack-pattern.json``), not assumed from memory — MISP's JSON schema
is stable and heavily depended-on (PyMISP, countless integrations), but
worth confirming rather than guessing, same as every other provider here.

Unlike OTX's dedicated ``TLP`` field, MISP represents TLP via tags (e.g.
``tlp:white``, ``tlp:clear``, ``tlp:amber``, ``tlp:red``) that may or may not
be present on a given event. Missing an explicit TLP tag is treated as safe
by default, mirroring OtxProvider's own handling of a missing TLP field —
consistent behavior across providers for the same underlying ambiguity.

MITRE ATT&CK technique IDs are extracted from ``Galaxy[].GalaxyCluster[]``:
primarily from ``meta.external_id`` (the authoritative field, confirmed
against the galaxy library above), with a regex fallback across
``tag_name``/``value`` in case a given MISP/galaxy version omits it.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

EVENTS_RESTSEARCH_PATH = "/events/restSearch"
HIGH_SIGNAL_TLP = {"white", "green", "clear"}
LOW_SIGNAL_TLP = {"red", "amber", "amber+strict"}

# Same pattern used in orchestrator.derive_research_topic and cti/rss.py —
# kept local rather than imported to avoid cross-module coupling.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_THREAT_LEVEL_NAMES = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}


class MispError(RuntimeError):
    """Raised when the MISP API request fails or returns unexpected data."""


@dataclass
class MispCursorState:
    """Incremental-sync cursor, persisted between polls."""

    last_timestamp: str = ""
    seen_ids_at_cursor: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> MispCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(
                last_timestamp=data.get("last_timestamp", ""),
                seen_ids_at_cursor=list(data.get("seen_ids_at_cursor", [])),
            )
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("MISP cursor file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(
            path,
            json.dumps(
                {"last_timestamp": self.last_timestamp, "seen_ids_at_cursor": self.seen_ids_at_cursor},
                indent=2,
            ),
        )

    def already_routed(self, event_timestamp: str, event_uuid: str) -> bool:
        return event_timestamp == self.last_timestamp and event_uuid in self.seen_ids_at_cursor

    def advance(self, event_timestamp: str, event_uuid: str) -> None:
        # MISP timestamps are Unix epoch seconds as strings -- compare
        # numerically, not lexicographically (unlike OTX's fixed-width
        # ISO8601 strings, these could differ in digit count). A stale/late
        # advance() call (e.g. from two overlapping polls) must not regress
        # the cursor backward -- that would make already-routed events look
        # unrouted again and get re-drafted under a new hunt ID.
        try:
            is_older = int(event_timestamp) < int(self.last_timestamp or 0)
        except ValueError:
            is_older = False  # non-numeric timestamp -- let it through rather than guess
        if is_older:
            log.warning(
                "Ignoring MISP cursor advance to an older timestamp (%s < %s); "
                "likely a stale advance() from an overlapping poll.",
                event_timestamp,
                self.last_timestamp,
            )
            return
        if event_timestamp != self.last_timestamp:
            self.last_timestamp = event_timestamp
            self.seen_ids_at_cursor = [event_uuid]
        elif event_uuid not in self.seen_ids_at_cursor:
            self.seen_ids_at_cursor.append(event_uuid)


class MispProvider(CTIProvider):
    """CTI provider backed by a MISP instance's published events."""

    name = "misp"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        cursor_file: Path,
        max_event_age_days: int = 30,
        page_limit: int = 20,
        request_timeout_sec: float = 30.0,
        verify_ssl: bool = True,
        client: httpx.Client | None = None,
    ):
        if not base_url:
            raise MispError("MISP base URL is required to use the misp CTI provider")
        if not api_key:
            raise MispError("MISP_API_KEY is required to use the misp CTI provider")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.cursor_file = cursor_file
        self.max_event_age_days = max_event_age_days
        self.page_limit = page_limit
        self.request_timeout_sec = request_timeout_sec
        self._client = client or httpx.Client(timeout=request_timeout_sec, verify=verify_ssl)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # --- CTIProvider interface -----------------------------------------------

    def next_item(self) -> CTIItem | None:
        cursor = MispCursorState.load(self.cursor_file)
        events = self._fetch_events_since(self._effective_since_timestamp(cursor.last_timestamp))
        candidate = self._pick_oldest_unrouted(events, cursor)
        if candidate is None:
            log.debug("No new high-signal MISP events since %s", cursor.last_timestamp or "(beginning)")
            return None
        return _event_to_cti_item(self.base_url, candidate)

    def acknowledge(self, item: CTIItem) -> None:
        event_timestamp = item.metadata.get("event_timestamp")
        event_uuid = item.metadata.get("event_uuid")
        if not event_uuid or not event_timestamp:
            log.warning("Cannot advance MISP cursor: item missing event metadata (%r)", item)
            return
        cursor = MispCursorState.load(self.cursor_file)
        cursor.advance(event_timestamp, event_uuid)
        cursor.save(self.cursor_file)

    # --- Internal --------------------------------------------------------------

    def _effective_since_timestamp(self, cursor_timestamp: str) -> str:
        """Floor the query's lower bound at ``max_event_age_days`` even on a
        fresh (empty) cursor.

        Without this, a MISP instance with any backlog of already-stale
        events (e.g. default bootstrap sample data, or feeds fetched for
        the first time after months of being disabled) starves the poll:
        ``order: timestamp ASC`` + a small ``page_limit`` means the oldest
        page is filled entirely with events ``_is_high_signal`` will reject
        as stale anyway, and genuinely fresh candidates -- sorted after
        that entire backlog -- are never reached. Applying the same
        freshness cutoff server-side guarantees the fetched page can
        actually contain a routable candidate.
        """
        cutoff_epoch = int((datetime.now(UTC) - timedelta(days=self.max_event_age_days)).timestamp())
        try:
            cursor_epoch = int(cursor_timestamp) if cursor_timestamp else 0
        except ValueError:
            cursor_epoch = 0
        return str(max(cursor_epoch, cutoff_epoch))

    def _fetch_events_since(self, timestamp_since: str | None) -> list[dict[str, Any]]:
        url = f"{self.base_url}{EVENTS_RESTSEARCH_PATH}"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {"published": 1, "limit": self.page_limit, "order": "timestamp ASC"}
        if timestamp_since:
            body["timestamp"] = timestamp_since

        try:
            resp = self._client.post(url, headers=headers, json=body)
        except httpx.RequestError as exc:
            raise MispError(f"MISP request failed: {exc}") from exc

        if resp.status_code == 403:
            raise MispError("MISP authentication failed (403) - check MISP_API_KEY")
        if resp.status_code != 200:
            raise MispError(f"MISP request failed: HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            data = resp.json()
        except ValueError as exc:
            raise MispError(f"MISP returned non-JSON response: {exc}") from exc

        # restSearch wraps results as {"response": [{"Event": {...}}, ...]}
        wrapped = data.get("response", [])
        return [item["Event"] for item in wrapped if isinstance(item, dict) and "Event" in item]

    def _pick_oldest_unrouted(
        self, events: list[dict[str, Any]], cursor: MispCursorState
    ) -> dict[str, Any] | None:
        cutoff = datetime.now(UTC) - timedelta(days=self.max_event_age_days)
        candidates = [e for e in events if _is_high_signal(e, cutoff)]
        candidates = [
            e for e in candidates if not cursor.already_routed(str(e.get("timestamp", "")), str(e.get("uuid", "")))
        ]
        if not candidates:
            return None
        candidates.sort(key=_event_sort_timestamp)
        return candidates[0]


def _event_sort_timestamp(event: dict[str, Any]) -> int:
    """Sort key for "oldest wins" selection. An event with a missing or
    invalid ``timestamp`` sorts as *newest* (sys.maxsize), not oldest (0) --
    an unverifiable age has no business jumping ahead of events we know for
    certain are older. (The previous `int(e.get("timestamp", 0) or 0)`
    defaulted a missing timestamp to 0 -- Unix epoch, "oldest possible" --
    the same backwards-fallback-direction bug found and fixed in the RSS
    provider's date sort.)
    """
    raw = event.get("timestamp")
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return sys.maxsize


def _is_high_signal(event: dict[str, Any], cutoff: datetime) -> bool:
    """Published, not explicitly TLP:RED/AMBER, not older than ``cutoff``."""
    if not (event.get("info") or "").strip():
        return False

    if not _is_published(event):
        return False

    tlp = _extract_tlp(event)
    if tlp is not None and tlp in LOW_SIGNAL_TLP:
        return False

    published_at = _event_datetime(event)
    return not (published_at is not None and published_at < cutoff)


def _is_published(event: dict[str, Any]) -> bool:
    value = event.get("published")
    if isinstance(value, bool):
        return value
    return str(value).strip() in {"1", "true", "True"}


def _extract_tlp(event: dict[str, Any]) -> str | None:
    """Return the TLP level from tags (e.g. 'white', 'red'), or None if untagged."""
    for tag in event.get("Tag", []) or []:
        name = str(tag.get("name", "")).lower()
        if name.startswith("tlp:"):
            return name.split(":", 1)[1].strip()
    return None


def _event_datetime(event: dict[str, Any]) -> datetime | None:
    timestamp = event.get("timestamp")
    if timestamp:
        try:
            return datetime.fromtimestamp(int(timestamp), tz=UTC)
        except (TypeError, ValueError):
            pass
    date_str = event.get("date")
    if date_str:
        try:
            return datetime.strptime(str(date_str), "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def _extract_techniques(event: dict[str, Any]) -> list[str]:
    """MITRE technique IDs from Galaxy/GalaxyCluster metadata, with a regex fallback."""
    techniques: set[str] = set()
    for galaxy in event.get("Galaxy", []) or []:
        for cluster in galaxy.get("GalaxyCluster", []) or []:
            external_id = cluster.get("meta", {}).get("external_id")
            if isinstance(external_id, list):
                techniques.update(str(x) for x in external_id if _TECHNIQUE_RE.fullmatch(str(x)))
            elif isinstance(external_id, str) and _TECHNIQUE_RE.fullmatch(external_id):
                techniques.add(external_id)
            # Fallback: some galaxy/version combinations omit meta.external_id.
            for field_value in (cluster.get("tag_name", ""), cluster.get("value", "")):
                techniques.update(_TECHNIQUE_RE.findall(str(field_value)))
    # Also scan flat event-level tags (e.g. "misp-galaxy:mitre-attack-pattern=...").
    for tag in event.get("Tag", []) or []:
        techniques.update(_TECHNIQUE_RE.findall(str(tag.get("name", ""))))
    return sorted(techniques)


def _event_to_cti_item(base_url: str, event: dict[str, Any]) -> CTIItem:
    timestamp = str(event.get("timestamp", ""))
    received_at = _event_datetime(event) or datetime.now(UTC)
    event_id = str(event.get("id", ""))
    return CTIItem(
        content=_event_to_blurb(base_url, event),
        source="misp",
        received_at=received_at,
        identifier=str(event.get("uuid", "")),
        metadata={
            "event_uuid": str(event.get("uuid", "")),
            "event_id": event_id,
            "event_timestamp": timestamp,
            "event_info": event.get("info", ""),
        },
        title=str(event.get("info") or ""),
        source_url=f"{base_url}/events/view/{event_id}" if event_id else "",
    )


def _event_to_blurb(base_url: str, event: dict[str, Any]) -> str:
    """Condense a MISP event into a text blurb for hypothesis-generator."""
    info = event.get("info") or "Untitled event"
    org = (event.get("Orgc") or {}).get("name") or "Unknown"
    threat_level = _THREAT_LEVEL_NAMES.get(str(event.get("threat_level_id", "")), "Unknown")
    tlp = _extract_tlp(event) or "unspecified"
    techniques = _extract_techniques(event)
    event_id = event.get("id", "")

    tags = [
        t.get("name", "")
        for t in event.get("Tag", []) or []
        if t.get("name") and not t["name"].lower().startswith(("tlp:", "misp-galaxy:"))
    ]

    attribute_counts: dict[str, int] = {}
    for attr in event.get("Attribute", []) or []:
        atype = attr.get("type", "unknown")
        attribute_counts[atype] = attribute_counts.get(atype, 0) + 1
    attribute_summary = ", ".join(f"{t} ({c})" for t, c in sorted(attribute_counts.items()))

    lines = [f"MISP Event: {info}", f"Org: {org}", f"Threat Level: {threat_level}", f"TLP: {tlp}"]
    if tags:
        lines.append(f"Tags: {', '.join(tags[:10])}")
    if techniques:
        lines.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
    if attribute_counts:
        lines.append(f"Attributes ({sum(attribute_counts.values())} total): {attribute_summary}")
    if event_id:
        lines.append(f"Link: {base_url}/events/view/{event_id}")

    return "\n".join(lines)
