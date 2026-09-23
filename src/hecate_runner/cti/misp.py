"""MISP (Malware Information Sharing Platform) CTI provider.

Polls ``POST /events/restSearch`` for events modified since a persisted
cursor, filters for high-signal events (published, not TLP:RED/AMBER, and by
default carrying a galaxy cluster), and returns the oldest unrouted candidate
as a ``CTIItem``.

Two knobs shape *which* events reach the orchestrator, and they are meant to
be used together:

``require_attack_technique`` (default off) is the stricter form of the
galaxy check: it demands the event actually map to ATT&CK techniques, not
merely carry some galaxy cluster. An event tagged only with a threat-actor
or malware galaxy passes ``require_galaxy`` and still yields no techniques,
so it can only become an indicator sweep. Turn it on to route only events a
behavioural hunt can be built from; leave it off to keep sweeps flowing.

``require_galaxy`` (default on) keeps bulk indicator dumps out. They pass
every other filter -- published, TLP:white, recent -- but describe no
behavior, so they can only yield indicator-sweep drafts with no ATT&CK
mapping.

``backfill`` (default off) drops the freshness floor so the archive can be
walked oldest-first. A long-lived instance can hold years of curated events
that ``max_event_age_days`` puts permanently out of reach, while the recent
window is dominated by daily dump feeds.

``org_allowlist`` (default empty, i.e. off) restricts routing to named
organisations. galaxy presence separates curated events from dumps, but it
cannot separate a high-volume *curated* feed from the handful of
analyst-written events beside it -- on the reference instance one org
accounts for 856 of 872 routable events, enough to bury the rest for a year.

Alone, each is a trap: require_galaxy on a dump-heavy recent window starves
the poll, and backfill without it simply works through the dumps too.

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
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

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
                {
                    "last_timestamp": self.last_timestamp,
                    "seen_ids_at_cursor": self.seen_ids_at_cursor,
                },
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
        require_galaxy: bool = True,
        require_attack_technique: bool = False,
        org_allowlist: Iterable[str] | None = None,
        backfill: bool = False,
        max_pages_per_poll: int = 25,
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
        self.require_galaxy = require_galaxy
        self.require_attack_technique = require_attack_technique
        # Normalised once: matching is case-insensitive, and an empty/omitted
        # list must mean "every org is eligible", not "no org is".
        self.org_allowlist = frozenset(
            o.strip().lower() for o in (org_allowlist or ()) if o.strip()
        )
        self.backfill = backfill
        self.max_pages_per_poll = max_pages_per_poll
        self._client = client or httpx.Client(timeout=request_timeout_sec, verify=verify_ssl)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # --- CTIProvider interface -----------------------------------------------

    def next_item(self) -> CTIItem | None:
        """Walk forward from the cursor until a routable event is found.

        Several pages may be consumed in one call. A run of rejected events
        longer than one page is normal -- the reference instance carries a
        daily indicator-dump feed, so `require_galaxy` can reject hundreds in
        a row -- and advancing only one page per poll made the first backfill
        candidate take 25 polls to reach. Walking pages here turns that into
        a single call, while `max_pages_per_poll` still bounds the work.

        Pages are fetched metadata-only. Everything selection needs (info,
        published, Tag/TLP, Galaxy, timestamp) is present without attributes,
        and attributes are the bulk of the payload -- a page of dump events
        measured ~4MB with them and ~160KB without. Only the winner is then
        re-fetched in full, since the CTI text summarises its inventory.
        """
        cursor = MispCursorState.load(self.cursor_file)

        for _ in range(self.max_pages_per_poll):
            events = self._fetch_events_since(
                self._effective_since_timestamp(cursor.last_timestamp), metadata=True
            )
            candidate = self._pick_oldest_unrouted(events, cursor)
            if candidate is not None:
                return _event_to_cti_item(self.base_url, self._hydrate(candidate))
            if len(events) < self.page_limit:
                break
            if not self._skip_exhausted_page(events, cursor):
                break

        log.debug("No new high-signal MISP events since %s", cursor.last_timestamp or "(beginning)")
        return None

    def _hydrate(self, event: dict[str, Any]) -> dict[str, Any]:
        """Re-fetch a metadata-only event with its attributes.

        Falls back to the metadata copy when the lookup fails: a draft naming
        the event without its indicator inventory is worth more than dropping
        a genuine candidate over a transient error.
        """
        uuid = str(event.get("uuid") or "")
        if not uuid:
            return event
        try:
            full = self._fetch_events_since(None, uuid=uuid)
        except MispError as exc:
            log.warning("Could not hydrate MISP event %s (%s); using metadata only", uuid, exc)
            return event

        # Match on uuid rather than trusting position. The filter is applied
        # server-side, so a response whose first entry is a different event
        # means the server ignored it -- routing that event's attributes under
        # the candidate's identity would silently describe the wrong intel.
        for hydrated in full:
            if str(hydrated.get("uuid") or "") == uuid:
                return hydrated
        log.warning("MISP hydrate for %s returned no matching event; using metadata only", uuid)
        return event

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
        if self.backfill:
            # Backfill exists precisely to reach past this floor. Returning the
            # raw cursor (empty on a fresh one, which omits the filter entirely)
            # lets `order: timestamp ASC` walk the archive from its beginning.
            # No exit condition is needed: the cursor advances forward every
            # poll, and once it passes the freshness cutoff this branch and the
            # floored one below return the same value, so backfill converges
            # into normal steady-state behavior on its own.
            return cursor_timestamp

        cutoff_epoch = int(
            (datetime.now(UTC) - timedelta(days=self.max_event_age_days)).timestamp()
        )
        try:
            cursor_epoch = int(cursor_timestamp) if cursor_timestamp else 0
        except ValueError:
            cursor_epoch = 0
        return str(max(cursor_epoch, cutoff_epoch))

    def _fetch_events_since(
        self, timestamp_since: str | None, metadata: bool = False, uuid: str | None = None
    ) -> list[dict[str, Any]]:
        url = f"{self.base_url}{EVENTS_RESTSEARCH_PATH}"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {"published": 1, "limit": self.page_limit, "order": "timestamp ASC"}
        if metadata:
            # Selection needs no attributes, and they are ~96% of the payload.
            body["metadata"] = 1
        if uuid:
            body["uuid"] = uuid
            body["limit"] = 1
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
        cutoff = (
            None if self.backfill else datetime.now(UTC) - timedelta(days=self.max_event_age_days)
        )
        candidates = [
            e
            for e in events
            if _is_high_signal(
                e,
                cutoff,
                require_galaxy=self.require_galaxy,
                org_allowlist=self.org_allowlist,
                require_attack_technique=self.require_attack_technique,
            )
        ]
        candidates = [
            e
            for e in candidates
            if not cursor.already_routed(str(e.get("timestamp", "")), str(e.get("uuid", "")))
        ]
        if not candidates:
            return None
        candidates.sort(key=_event_sort_timestamp)
        return candidates[0]

    def _skip_exhausted_page(self, events: list[dict[str, Any]], cursor: MispCursorState) -> bool:
        """Advance the cursor past a full page that yielded no candidate.

        The cursor normally only moves in acknowledge(), i.e. when an event is
        actually routed. That is fine when the filters reject a minority of a
        page, but `require_galaxy` rejects the ThreatFox-style indicator dumps
        that arrive dozens in a row -- a full page of them yields no candidate,
        so no acknowledge(), so no advance, and every later poll refetches the
        identical page forever. Stepping over an exhausted page is what lets
        the poll walk through a long run of unwanted events.

        Only *full* pages are skipped. A short page means we have reached the
        end of what MISP currently holds, and advancing there would step over
        events that simply have not arrived yet.
        """
        if len(events) < self.page_limit:
            return False

        timestamps = [t for t in (_event_sort_timestamp(e) for e in events) if t != sys.maxsize]
        if not timestamps:
            return False
        newest = max(timestamps)
        try:
            if newest <= int(cursor.last_timestamp or 0):
                return False
        except ValueError:
            return False

        newest_str = str(newest)
        log.info(
            "MISP page of %d events yielded no routable candidate; advancing cursor to %s "
            "so the next poll makes progress.",
            len(events),
            newest_str,
        )
        cursor.last_timestamp = newest_str
        # Carry forward the uuids sitting exactly at the new cursor. Clearing
        # the list instead would make any already-routed event at that same
        # timestamp look unrouted again and get re-drafted under a new hunt ID.
        cursor.seen_ids_at_cursor = [
            str(e.get("uuid", ""))
            for e in events
            if str(e.get("timestamp", "")) == newest_str and e.get("uuid")
        ]
        cursor.save(self.cursor_file)
        return True


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


def _has_galaxy_cluster(event: dict[str, Any]) -> bool:
    """Whether the event carries any MISP galaxy cluster.

    Galaxy presence is the cleanest available separator between a curated,
    analyst-written event and a bulk indicator dump. Measured across the
    reference instance: every Rectifyq and CERT-FR event carried clusters and
    averaged ~25 attributes, while every abuse.ch/ThreatFox event carried none
    and averaged ~734. The dumps describe no behavior, so they can only ever
    produce indicator-sweep drafts with no ATT&CK mapping.

    Any cluster counts, not just an ATT&CK technique one: threat-actor and
    malware galaxies mark the same "an analyst curated this" signal, and
    requiring a technique specifically would drop good events whose galaxies
    name only the actor.
    """
    return any(galaxy.get("GalaxyCluster") for galaxy in event.get("Galaxy", []) or [])


def _is_high_signal(
    event: dict[str, Any],
    cutoff: datetime | None,
    require_galaxy: bool = False,
    org_allowlist: frozenset[str] = frozenset(),
    require_attack_technique: bool = False,
) -> bool:
    """Published, not explicitly TLP:RED/AMBER, and newer than ``cutoff``.

    ``cutoff`` of None disables the age check entirely -- that is backfill,
    where reaching deliberately old events is the whole point.

    An empty ``org_allowlist`` disables the org check; a non-empty one admits
    only its members, which is how a single high-volume feed is kept from
    burying the analyst-written events behind it.
    """
    if not (event.get("info") or "").strip():
        return False

    if not _is_published(event):
        return False

    tlp = _extract_tlp(event)
    if tlp is not None and tlp in LOW_SIGNAL_TLP:
        return False

    if require_galaxy and not _has_galaxy_cluster(event):
        return False

    if org_allowlist and _event_org(event).lower() not in org_allowlist:
        return False

    # `require_galaxy` asks "is this curated"; this asks "can this produce a
    # behavioural hunt". They are not the same question: a MISP event tagged
    # only with a threat-actor or malware galaxy carries a cluster but no
    # attack-pattern, so it passes the first check, yields no technique IDs,
    # and lands on the indicator-sweep path. Observed live on the 17:46 poll.
    if require_attack_technique and not _extract_techniques(event):
        return False

    if cutoff is None:
        return True

    published_at = _event_datetime(event)
    return not (published_at is not None and published_at < cutoff)


def _event_org(event: dict[str, Any]) -> str:
    """Owning organisation name, preferring Orgc (the creator) over Org.

    On a synchronised instance Org is the local host for everything it pulled,
    so filtering on it would match every event or none; Orgc survives the sync
    and is what actually identifies who wrote the event.
    """
    for key in ("Orgc", "Org"):
        block = event.get(key)
        if isinstance(block, dict):
            name = str(block.get("name") or "").strip()
            if name:
                return name
    return ""


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


# Types that name something a detection rule can actually match on. `link`
# and `comment` are context for a human, not selection criteria, and feeding
# them to a rule generator invites rules keyed on a blog URL.
_DETECTABLE_ATTR_TYPES = frozenset(
    {
        "ip-dst",
        "ip-src",
        "domain",
        "hostname",
        "url",
        "uri",
        "filename",
        "filepath",
        "md5",
        "sha1",
        "sha256",
        "regkey",
        "mutex",
    }
)


def _indicator_map(event: dict[str, Any]) -> dict[str, list[str]]:
    """Group an event's detectable attribute values by type.

    Bounded by the same rule as the blurb: a dump's hundreds of indicators
    describe a feed, not tradecraft, and would push a rule generator toward
    an indicator-match rule per line.
    """
    attributes = event.get("Attribute", []) or []
    if not attributes or len(attributes) > _MAX_ATTRS_INLINE:
        return {}
    grouped: dict[str, list[str]] = {}
    for attr in attributes:
        atype = str(attr.get("type") or "")
        value = str(attr.get("value") or "").strip()
        if not value or atype not in _DETECTABLE_ATTR_TYPES:
            continue
        grouped.setdefault(atype, []).append(value[:_MAX_VALUE_CHARS])
    return grouped


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
            "entry_tags": [str(t.get("name", "")) for t in event.get("Tag", []) or [] if t.get("name")],
            # Structured alongside the rendered blurb so downstream steps
            # (Sigma drafting) get typed values instead of re-parsing prose.
            "indicators": _indicator_map(event),
            "techniques": _extract_techniques(event),
        },
        title=str(event.get("info") or ""),
        source_url=f"{base_url}/events/view/{event_id}" if event_id else "",
    )


# A curated event's attribute *values* are the most actionable thing it
# carries -- the C2 domains and the masquerading file path are what a hunt
# query is actually built from. A dump's several hundred are noise that would
# swamp the prompt and teach the model to write indicator sweeps. So values
# are inlined only for events small enough to have been written by hand, and
# capped per type so one long URL list cannot crowd out the filenames.
_MAX_ATTRS_INLINE = 40
_MAX_VALUES_PER_TYPE = 6
_MAX_VALUE_CHARS = 120


def _attribute_detail_lines(event: dict[str, Any]) -> list[str]:
    """Render concrete indicator values for a small, curated event.

    Returns no lines at all for a bulk dump: past ``_MAX_ATTRS_INLINE`` the
    values stop being evidence of tradecraft and become a feed, which the
    counts line already summarises adequately.
    """
    attributes = event.get("Attribute", []) or []
    if not attributes or len(attributes) > _MAX_ATTRS_INLINE:
        return []

    by_type: dict[str, list[str]] = {}
    notes: list[str] = []
    for attr in attributes:
        value = str(attr.get("value") or "").strip()
        if not value:
            continue
        atype = str(attr.get("type") or "unknown")
        comment = str(attr.get("comment") or "").strip()
        # A "comment" attribute's value *is* the analyst's prose -- on the
        # reference event that is where the Cobalt Strike beacon config was
        # recorded, which no indicator list would have conveyed.
        if atype == "comment":
            notes.append(value[:400])
            continue
        rendered = value[:_MAX_VALUE_CHARS]
        if comment:
            rendered = f"{rendered} ({comment[:60]})"
        by_type.setdefault(atype, []).append(rendered)

    lines: list[str] = []
    if by_type:
        lines.append("Key indicators:")
        for atype in sorted(by_type):
            values = by_type[atype]
            shown = values[:_MAX_VALUES_PER_TYPE]
            suffix = f" (+{len(values) - len(shown)} more)" if len(values) > len(shown) else ""
            lines.append(f"  {atype}: {', '.join(shown)}{suffix}")
    for note in notes:
        lines.append(f"Analyst note: {note}")
    return lines


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
        lines.append(f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}")
    if attribute_counts:
        lines.append(f"Attributes ({sum(attribute_counts.values())} total): {attribute_summary}")
    # Kept strictly below the counts line, which indicator_sweep.py parses by
    # regex -- these detail lines must never displace or reshape it.
    lines.extend(_attribute_detail_lines(event))
    if event_id:
        lines.append(f"Link: {base_url}/events/view/{event_id}")

    return "\n".join(lines)
