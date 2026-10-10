"""AlienVault OTX (Open Threat Exchange) CTI provider.

Polls the ``/api/v1/pulses/subscribed`` endpoint for pulses modified since a
persisted cursor, filters for high-signal pulses (TLP white/green, has an
ATT&CK mapping, not stale), and returns the oldest unrouted candidate as a
``CTIItem``. Structured pulse data is condensed into a text blurb rather than
passed through as raw JSON — the hypothesis-generator model does better on
prose, and it keeps the input well under budget even for pulses with
hundreds of indicators.

Cursor state (last routed pulse's ``modified`` timestamp, plus pulse IDs
seen at that exact timestamp to break ties) is persisted to disk so repeat
polls don't re-ingest a pulse and a crash mid-cycle doesn't lose position.
Like ``FileQueueProvider``, each call is stateless against the API — nothing
is cached in memory between ``next_item()`` calls, so a call is always a
fresh, small (<= ``page_limit`` results) fetch from the last known cursor.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider, extract_article_text

log = logging.getLogger(__name__)

OTX_BASE_URL = "https://otx.alienvault.com"
PULSES_PATH = "/api/v1/pulses/subscribed"
HIGH_SIGNAL_TLP = {"white", "green"}


class OtxError(RuntimeError):
    """Raised when the OTX API request fails or returns unexpected data."""


@dataclass
class OtxCursorState:
    """Incremental-sync cursor, persisted between polls."""

    last_modified: str = ""
    seen_ids_at_cursor: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> OtxCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(
                last_modified=data.get("last_modified", ""),
                seen_ids_at_cursor=list(data.get("seen_ids_at_cursor", [])),
            )
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("OTX cursor file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(
            path,
            json.dumps(
                {
                    "last_modified": self.last_modified,
                    "seen_ids_at_cursor": self.seen_ids_at_cursor,
                },
                indent=2,
            ),
        )

    def already_routed(self, pulse_modified: str, pulse_id: str) -> bool:
        return pulse_modified == self.last_modified and pulse_id in self.seen_ids_at_cursor

    def advance(self, pulse_modified: str, pulse_id: str) -> None:
        # ISO8601 timestamps sort lexicographically the same as chronologically.
        # A stale/late advance() call (e.g. from two overlapping polls) must
        # not regress the cursor backward -- that would make already-routed
        # pulses look unrouted again and get re-drafted under a new hunt ID.
        if pulse_modified < self.last_modified:
            log.warning(
                "Ignoring OTX cursor advance to an older modified time (%s < %s); "
                "likely a stale advance() from an overlapping poll.",
                pulse_modified,
                self.last_modified,
            )
            return
        if pulse_modified != self.last_modified:
            self.last_modified = pulse_modified
            self.seen_ids_at_cursor = [pulse_id]
        elif pulse_id not in self.seen_ids_at_cursor:
            self.seen_ids_at_cursor.append(pulse_id)


class OtxProvider(CTIProvider):
    """CTI provider backed by AlienVault OTX subscribed pulses."""

    name = "otx"

    def __init__(
        self,
        api_key: str,
        cursor_file: Path,
        base_url: str = OTX_BASE_URL,
        page_limit: int = 20,
        max_pulse_age_days: int = 30,
        max_pages: int = 10,
        request_timeout_sec: float = 30.0,
        client: httpx.Client | None = None,
    ):
        if not api_key:
            raise OtxError("OTX_API_KEY is required to use the otx CTI provider")
        self.api_key = api_key
        self.cursor_file = cursor_file
        self.base_url = base_url.rstrip("/")
        self.page_limit = page_limit
        self.max_pulse_age_days = max_pulse_age_days
        self.max_pages = max_pages
        self.request_timeout_sec = request_timeout_sec
        self._client = client or httpx.Client(timeout=request_timeout_sec)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # --- CTIProvider interface -----------------------------------------------

    def next_item(self) -> CTIItem | None:
        cursor = OtxCursorState.load(self.cursor_file)
        pulses = self._fetch_pulses_since(cursor.last_modified or None)
        candidate, aged_out, backlog = self._pick_oldest_unrouted(pulses, cursor)
        if candidate is None:
            log.debug(
                "No new high-signal OTX pulses since %s", cursor.last_modified or "(beginning)"
            )
            return None
        item = _pulse_to_cti_item(candidate)
        item.metadata["backlog"] = backlog
        if aged_out:
            # Handed over rather than skipped, so the orchestrator parks it:
            # skipping is what let 23 high-signal pulses vanish without trace.
            item.metadata["aged_out"] = (
                f"waited in the OTX backlog past the {self.max_pulse_age_days}-day "
                "freshness limit before a draft slot was free"
            )
        return item

    def acknowledge(self, item: CTIItem) -> None:
        pulse_id = item.metadata.get("pulse_id")
        pulse_modified = item.metadata.get("pulse_modified")
        if not pulse_id or not pulse_modified:
            log.warning("Cannot advance OTX cursor: item missing pulse metadata (%r)", item)
            return
        cursor = OtxCursorState.load(self.cursor_file)
        cursor.advance(pulse_modified, pulse_id)
        cursor.save(self.cursor_file)

    # --- Internal --------------------------------------------------------------

    def _fetch_pulses_since(self, modified_since: str | None) -> list[dict[str, Any]]:
        """Every pulse modified since the cursor, up to ``max_pages`` pages.

        OTX returns newest first, so the oldest pulses -- the ones oldest-first
        selection wants -- are on the *last* pages. Reading page 1 alone meant
        "oldest of the newest 20": once more than 20 were waiting, older pulses
        slid off the page as new ones arrived, the cursor then advanced past
        them, and they were never seen again. Measured on the live feed: 23 of
        40 high-signal pulses since 15 Sep, including Hangro (47 IOCs) and
        SilkParasite (102), lost that way.
        """
        pulses: list[dict[str, Any]] = []
        for page in range(1, self.max_pages + 1):
            data = self._fetch_page(modified_since, page)
            results = list(data.get("results", []))
            pulses.extend(results)
            if not data.get("next") or len(results) < self.page_limit:
                return pulses
        log.warning(
            "OTX backlog exceeds %d pages (%d pulses) since %s; the oldest beyond that "
            "are not visible this cycle",
            self.max_pages,
            len(pulses),
            modified_since or "(beginning)",
        )
        return pulses

    def _fetch_page(self, modified_since: str | None, page: int) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": self.page_limit, "page": page}
        if modified_since:
            params["modified_since"] = modified_since

        url = f"{self.base_url}{PULSES_PATH}"
        headers = {"X-OTX-API-KEY": self.api_key}

        try:
            resp = self._client.get(url, params=params, headers=headers)
        except httpx.RequestError as exc:
            raise OtxError(f"OTX request failed: {exc}") from exc

        if resp.status_code == 401:
            raise OtxError("OTX authentication failed (401) - check OTX_API_KEY")
        if resp.status_code == 429:
            raise OtxError("OTX rate limit exceeded (429)")
        if resp.status_code != 200:
            raise OtxError(f"OTX request failed: HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            data = resp.json()
        except ValueError as exc:
            raise OtxError(f"OTX returned non-JSON response: {exc}") from exc
        return data if isinstance(data, dict) else {}

    def _pick_oldest_unrouted(
        self, pulses: list[dict[str, Any]], cursor: OtxCursorState
    ) -> tuple[dict[str, Any] | None, bool, int]:
        """(oldest unrouted pulse, whether it aged out waiting, fresh backlog size).

        A pulse that is high-signal in every way but age, and that crossed the
        freshness limit *while waiting in this backlog*, is returned flagged
        rather than filtered out, so it is parked with a reason instead of
        vanishing. "While waiting" means the cursor is set (a fresh install
        has no backlog), the pulse is past the cursor, and it was created
        within the last two age windows (an old pulse re-published today was
        never waiting). Anything else past the limit is skipped as before.
        """
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=self.max_pulse_age_days)
        expiry_floor = cutoff - timedelta(days=self.max_pulse_age_days)
        unrouted = [
            p
            for p in pulses
            if not cursor.already_routed(p.get("modified", ""), str(p.get("id", "")))
        ]
        fresh = [p for p in unrouted if _is_high_signal(p, cutoff)]
        aged: list[dict[str, Any]] = []
        if cursor.last_modified:
            for p in unrouted:
                created = _parse_otx_timestamp(p.get("created", ""))
                if (
                    created is not None
                    and expiry_floor <= created < cutoff
                    and _is_high_signal(p, expiry_floor)
                ):
                    aged.append(p)
        candidates = sorted([*fresh, *aged], key=_pulse_sort_key)
        if not candidates:
            return None, False, 0
        oldest = candidates[0]
        return oldest, oldest in aged, len(fresh)


def _pulse_sort_key(pulse: dict[str, Any]) -> datetime:
    """Sort key for "oldest wins" selection. A pulse with a missing or
    unparseable ``modified`` value sorts as *newest* (datetime.max), not
    oldest -- an unverifiable age has no business jumping ahead of pulses we
    know for certain are older. (The previous raw-string sort,
    `p.get("modified", "")`, defaulted a missing value to "" -- which sorts
    lexicographically before any real ISO8601 date string, i.e. "oldest
    possible" -- the same backwards-fallback-direction bug found and fixed
    in the RSS provider's date sort and MISP's timestamp sort.)
    """
    return _parse_otx_timestamp(pulse.get("modified", "")) or datetime.max.replace(tzinfo=UTC)


def _is_high_signal(pulse: dict[str, Any], cutoff: datetime) -> bool:
    """TLP white/green, has an ATT&CK mapping, not older than ``cutoff``."""
    if not (pulse.get("name") or "").strip():
        return False

    tlp = str(pulse.get("TLP") or pulse.get("tlp") or "white").lower()
    if tlp not in HIGH_SIGNAL_TLP:
        return False

    attack_ids = pulse.get("attack_ids") or []
    if not attack_ids:
        return False

    created = _parse_otx_timestamp(pulse.get("created", ""))
    return not (created is not None and created < cutoff)


# OTX pulses routinely carry hundreds of indicators from bulk feeds. The same
# bound the MISP provider uses applies: past this many, the list describes a
# feed rather than tradecraft, and handing it to a rule generator produces an
# indicator-match rule per line instead of a behavioural one.
#
# It was 40, which is not where curated reports stop: SentinelOne's
# TraderTraitor write-up carried 42 (hashes, IPs, domains, hostnames) and every
# value was dropped, so H-0007 reached the model and the Sigma generator with
# counts only. Hand-written reports run to low hundreds; bulk feeds run to
# many hundreds. The per-type cap below is what bounds the prompt.
_MAX_INDICATORS_INLINE = 200
_MAX_INDICATOR_VALUES_PER_TYPE = 10

# A CVE identifies a vulnerability, not an observable a detection rule can
# match on; the rest name something that appears in telemetry.
_NON_OBSERVABLE_OTX_TYPES = frozenset({"CVE"})

#: Matches the MISP provider's per-value ceiling.
_MAX_INDICATOR_VALUE_CHARS = 120


def _indicator_detail_lines(pulse: dict[str, Any]) -> list[str]:
    """Render concrete indicator values for a small, curated pulse.

    The counts line alone ("FileHash-SHA256 (13)") told the model how many
    indicators existed without telling it what any of them were, so a pulse
    carrying thirteen real hashes produced a hunt containing none of them.
    This is the OTX half of the MISP provider's ``_attribute_detail_lines``;
    the rendered shape is deliberately identical, because ``hunt_audit`` and
    the grounding audit already parse the MISP one.

    Returns no lines for a bulk dump: past ``_MAX_INDICATORS_INLINE`` the
    values stop being evidence of tradecraft and become a feed, which the
    counts line summarises adequately.

    Unlike ``_indicator_map``, CVEs are kept. That map feeds Sigma drafting,
    where a CVE is not something a rule can match; this blurb feeds the model
    and the grounding corpus, where naming the CVE the source actually cited
    is what lets the audit tell it apart from an invented one.
    """
    indicators = pulse.get("indicators") or []
    if not indicators or len(indicators) > _MAX_INDICATORS_INLINE:
        return []

    grouped: dict[str, list[str]] = {}
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        itype = str(ind.get("type") or "")
        value = str(ind.get("indicator") or "").strip()
        if not value or not itype:
            continue
        grouped.setdefault(itype, []).append(value[:_MAX_INDICATOR_VALUE_CHARS])

    if not grouped:
        return []

    lines = ["Key indicators:"]
    for itype in sorted(grouped):
        values = grouped[itype]
        shown = values[:_MAX_INDICATOR_VALUES_PER_TYPE]
        suffix = f" (+{len(values) - len(shown)} more)" if len(values) > len(shown) else ""
        lines.append(f"  {itype}: {', '.join(shown)}{suffix}")
    return lines


def _indicator_map(pulse: dict[str, Any]) -> dict[str, list[str]]:
    """Group a pulse's observable indicator values by OTX type."""
    indicators = pulse.get("indicators") or []
    if not indicators or len(indicators) > _MAX_INDICATORS_INLINE:
        return {}
    grouped: dict[str, list[str]] = {}
    for ind in indicators:
        if not isinstance(ind, dict):
            continue
        itype = str(ind.get("type") or "")
        value = str(ind.get("indicator") or "").strip()
        if not value or not itype or itype in _NON_OBSERVABLE_OTX_TYPES:
            continue
        bucket = grouped.setdefault(itype, [])
        if len(bucket) < _MAX_INDICATOR_VALUES_PER_TYPE:
            bucket.append(value[:_MAX_INDICATOR_VALUE_CHARS])
    return grouped


def _pulse_to_cti_item(pulse: dict[str, Any]) -> CTIItem:
    modified = pulse.get("modified", "")
    received_at = _parse_otx_timestamp(modified) or datetime.now(UTC)
    references = pulse.get("references") or []
    return CTIItem(
        content=_pulse_to_blurb(pulse),
        source="otx",
        received_at=received_at,
        identifier=str(pulse.get("id", "")),
        metadata={
            "pulse_id": str(pulse.get("id", "")),
            "pulse_modified": modified,
            "pulse_name": pulse.get("name", ""),
            "entry_tags": pulse.get("tags") or [],
            # Structured alongside the blurb, matching the MISP provider, so
            # Sigma drafting gets typed values rather than re-parsing prose.
            "indicators": _indicator_map(pulse),
            "techniques": [
                a.get("id", "")
                for a in (pulse.get("attack_ids") or [])
                if isinstance(a, dict) and a.get("id")
            ],
        },
        title=str(pulse.get("name") or ""),
        source_url=str(references[0]) if references else "",
    )


def _pulse_to_blurb(pulse: dict[str, Any]) -> str:
    """Condense a structured OTX pulse into a text blurb for hypothesis-generator."""
    name = pulse.get("name") or "Untitled pulse"
    adversary = pulse.get("adversary") or "Unknown"
    tags = pulse.get("tags") or []
    description = (pulse.get("description") or "").strip()
    attack_ids = pulse.get("attack_ids") or []
    techniques = [a.get("id", "") for a in attack_ids if isinstance(a, dict) and a.get("id")]
    indicators = pulse.get("indicators") or []
    references = pulse.get("references") or []

    indicator_counts: dict[str, int] = {}
    for ind in indicators:
        itype = ind.get("type", "unknown") if isinstance(ind, dict) else "unknown"
        indicator_counts[itype] = indicator_counts.get(itype, 0) + 1
    indicator_summary = ", ".join(
        f"{itype} ({count})" for itype, count in sorted(indicator_counts.items())
    )
    
    extracted_text = ""
    if references:
        extracted_text = extract_article_text(references[0])

    lines = [f"OTX Pulse: {name}", f"Adversary/Attribution: {adversary}"]
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")
    if techniques:
        lines.append(f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}")
    
    if extracted_text:
        lines.append(f"Description: {description[:1500]}")
        lines.append(f"Reference Article Content:\n{extracted_text}")
    elif description:
        lines.append(f"Description: {description[:1500]}")
        
    if indicators:
        lines.append(f"Indicators ({len(indicators)} total): {indicator_summary}")
        lines.extend(_indicator_detail_lines(pulse))
    if references:
        lines.append(f"References: {', '.join(references[:5])}")

    return "\n".join(lines)


def _parse_otx_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None
