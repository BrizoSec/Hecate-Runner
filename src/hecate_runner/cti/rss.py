"""RSS/Atom CTI provider.

Polls a configured list of security research feed URLs, filters for entries
within a max age, and returns the oldest unrouted candidate across all
feeds as a ``CTIItem``. Unlike OTX's crowdsourced pulse firehose (which
needs TLP + ATT&CK-mapping filters to separate signal from noise), the
"high signal" filter here is mostly the curation itself: every feed in the
configured list is a hand-picked, reputable CTI research source, not an
open subscription firehose. A MITRE technique ID is still extracted from
the title/summary when present (same regex the orchestrator already uses
to seed research topics) so it can ride along as structured metadata, but
its absence doesn't exclude an entry — plenty of good tradecraft writeups
describe TTPs in prose without citing a T-code.

Cursor state (the set of already-routed entry IDs per feed URL) is
persisted to disk so repeat polls don't re-ingest an entry, and a crash
mid-cycle doesn't lose position. Unlike OTX's incremental "modified since"
API sync, RSS/Atom feeds return their full current window on every
request with no server-side cursor — so, unlike OtxCursorState, a single
last-seen ID per feed isn't enough: only one candidate is acknowledged per
poll cycle (the globally oldest across all feeds), so a feed with several
unrouted entries has older ones routed one at a time across many cycles,
and the single last-seen ID gets overwritten — and its previous value
forgotten — every time a newer entry in the same feed is later
acknowledged. The full per-feed seen-ID set avoids that. Each feed's
failure (network error, malformed XML, blocked request) is isolated — one
broken feed doesn't stop entries from other configured feeds being
considered.
"""

from __future__ import annotations

import html
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import feedparser
import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

REQUEST_USER_AGENT = "hecate-runner-cti-poller/1.0 (+https://github.com/BrizoSec/hecate-runner)"

# Same pattern used in orchestrator.derive_research_topic — kept separate
# rather than imported to avoid a cti/ -> orchestrator dependency cycle.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_HTML_TAG_RE = re.compile(r"<[^>]+>")


class RssError(RuntimeError):
    """Raised when an RSS provider operation fails outright (not per-feed)."""


#: Cap on remembered entry IDs per feed, oldest dropped first. Bounds file
#: growth indefinitely while comfortably covering any real feed's window
#: (typically 10-50 entries) many times over.
_MAX_SEEN_IDS_PER_FEED = 500


@dataclass
class RssCursorState:
    """Per-feed set of already-routed entry IDs, persisted between polls."""

    seen_ids: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> RssCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            seen_ids = data.get("seen_ids")
            if seen_ids is None:
                # Back-compat with the old single-last-seen-ID format.
                seen_ids = {
                    feed: [entry_id] for feed, entry_id in data.get("last_seen_id", {}).items()
                }
            return cls(seen_ids={feed: list(ids) for feed, ids in seen_ids.items()})
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("RSS cursor file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps({"seen_ids": self.seen_ids}, indent=2))

    def already_routed(self, feed_url: str, entry_id: str) -> bool:
        return self.already_routed_any(feed_url, [entry_id])

    def already_routed_any(self, feed_url: str, identifiers: Iterable[str]) -> bool:
        """True if *any* of an entry's identifiers has been routed before.

        Matching on more than one identifier is what makes dedup survive a
        feed whose GUID isn't stable. CrowdStrike's blog re-issued a
        different ``<guid>`` for an unchanged post on successive fetches --
        four distinct ``?p=NNNNNN`` ids for one article -- while its link
        stayed constant, so an id-only check re-routed it once per poll and
        produced four identical hunts and four identical research documents
        from a single article.
        """
        seen = self.seen_ids.get(feed_url, [])
        return any(identifier in seen for identifier in identifiers)

    def advance(self, feed_url: str, entry_id: str) -> None:
        self.advance_all(feed_url, [entry_id])

    def advance_all(self, feed_url: str, identifiers: Iterable[str]) -> None:
        """Remember every identifier an entry was matched on.

        Recording all of them (not just the primary id) is what lets a later
        poll recognise the same entry through whichever identifier happens to
        be stable for that feed.
        """
        ids = self.seen_ids.setdefault(feed_url, [])
        for identifier in identifiers:
            if identifier and identifier not in ids:
                ids.append(identifier)
        if len(ids) > _MAX_SEEN_IDS_PER_FEED:
            del ids[: len(ids) - _MAX_SEEN_IDS_PER_FEED]


class RssProvider(CTIProvider):
    """CTI provider backed by a configured list of security research RSS/Atom feeds."""

    name = "rss"

    def __init__(
        self,
        feed_urls: list[str],
        cursor_file: Path,
        max_entry_age_days: int = 14,
        request_timeout_sec: float = 15.0,
        client: httpx.Client | None = None,
    ):
        if not feed_urls:
            raise RssError("At least one feed URL is required to use the rss CTI provider")
        self.feed_urls = feed_urls
        self.cursor_file = cursor_file
        self.max_entry_age_days = max_entry_age_days
        self.request_timeout_sec = request_timeout_sec
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={"User-Agent": REQUEST_USER_AGENT},
            follow_redirects=True,
        )
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # --- CTIProvider interface -----------------------------------------------

    def next_item(self) -> CTIItem | None:
        cursor = RssCursorState.load(self.cursor_file)
        cutoff = datetime.now(UTC) - timedelta(days=self.max_entry_age_days)

        candidates: list[tuple[str, dict[str, Any]]] = []
        for feed_url in self.feed_urls:
            try:
                entries = self._fetch_entries(feed_url)
            except RssError as exc:
                log.warning("Skipping feed %s (%s)", feed_url, exc)
                continue

            for entry in entries:
                identifiers = _entry_identifiers(entry)
                if not identifiers or cursor.already_routed_any(feed_url, identifiers):
                    continue
                published = _entry_published(entry)
                if published is not None and published < cutoff:
                    continue
                candidates.append((feed_url, entry))

        if not candidates:
            log.debug("No new entries across %d configured RSS feeds", len(self.feed_urls))
            return None

        # Oldest unrouted candidate first, mirroring OtxProvider — a stable,
        # fair ordering across feeds rather than always favoring whichever
        # feed happens to be checked first. An entry whose date we couldn't
        # parse at all sorts as *newest* (lowest priority), not oldest: an
        # unverifiable age has no business jumping ahead of entries we know
        # for certain are older. (This used to fall back to datetime.min --
        # oldest-possible -- which let entries with unparseable dates, e.g.
        # a feed emitting a non-RFC822 format, win "oldest" against every
        # other feed indefinitely, regardless of their actual age.)
        candidates.sort(
            key=lambda pair: _entry_published(pair[1]) or datetime.max.replace(tzinfo=UTC)
        )
        feed_url, entry = candidates[0]
        return _entry_to_cti_item(feed_url, entry)

    def acknowledge(self, item: CTIItem) -> None:
        feed_url = item.metadata.get("feed_url")
        identifiers = [
            value
            for value in (item.metadata.get("entry_id"), item.metadata.get("entry_link"))
            if value
        ]
        if not feed_url or not identifiers:
            log.warning("Cannot advance RSS cursor: item missing feed metadata (%r)", item)
            return
        cursor = RssCursorState.load(self.cursor_file)
        cursor.advance_all(feed_url, identifiers)
        cursor.save(self.cursor_file)

    # --- Internal --------------------------------------------------------------

    def _fetch_entries(self, feed_url: str) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(feed_url)
        except httpx.RequestError as exc:
            raise RssError(f"request failed: {exc}") from exc

        if resp.status_code != 200:
            raise RssError(f"HTTP {resp.status_code}")

        parsed = feedparser.parse(resp.content)
        if parsed.bozo and not parsed.entries:
            raise RssError(f"unparseable feed: {parsed.get('bozo_exception', 'unknown error')}")

        return list(parsed.entries)


def _entry_id(entry: dict[str, Any]) -> str:
    return str(entry.get("id") or entry.get("link") or "")


def _entry_identifiers(entry: dict[str, Any]) -> list[str]:
    """Every identifier an entry can be recognised by, most specific first.

    ``id`` alone is not enough: it is whatever the feed chooses to put in
    ``<guid>``, and a feed that regenerates it per fetch defeats dedup
    entirely. The link is the article's stable identity in practice, so both
    are checked and both are remembered.
    """
    identifiers: list[str] = []
    for key in ("id", "link"):
        value = str(entry.get(key) or "").strip()
        if value and value not in identifiers:
            identifiers.append(value)
    return identifiers


# feedparser's own date parser misses some real-world formats it still can't
# make sense of -- e.g. CrowdStrike's blog emits `published`/`updated` as
# "Jul 15, 2026 00:00:00-0500" (no weekday, comma-separated, no space before
# the UTC offset), which isn't RFC822 and feedparser leaves *_parsed as None
# for. Tried as a fallback, in order, against the raw (unparsed) string
# fields when feedparser's own parse comes back empty.
_FALLBACK_DATE_FORMATS = (
    "%b %d, %Y %H:%M:%S%z",  # CrowdStrike: "Jul 15, 2026 00:00:00-0500"
)


def _entry_published(entry: dict[str, Any]) -> datetime | None:
    parsed_time = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed_time:
        try:
            # Indexed rather than `datetime(*parsed_time[:6], tzinfo=UTC)`: feedparser
            # gives no type stubs, so a starred unpack of an untyped slice reads to
            # mypy as possibly colliding with the explicit tzinfo kwarg.
            return datetime(
                parsed_time[0],
                parsed_time[1],
                parsed_time[2],
                parsed_time[3],
                parsed_time[4],
                parsed_time[5],
                tzinfo=UTC,
            )
        except (TypeError, ValueError, IndexError):
            pass

    raw = entry.get("published") or entry.get("updated")
    if raw:
        for fmt in _FALLBACK_DATE_FORMATS:
            try:
                return datetime.strptime(raw, fmt).astimezone(UTC)
            except ValueError:
                continue

    return None


def _strip_html(raw: str) -> str:
    return html.unescape(_HTML_TAG_RE.sub("", raw or "")).strip()


def _entry_to_cti_item(feed_url: str, entry: dict[str, Any]) -> CTIItem:
    entry_id = _entry_id(entry)
    published = _entry_published(entry) or datetime.now(UTC)
    return CTIItem(
        content=_entry_to_blurb(feed_url, entry),
        source="rss",
        received_at=published,
        identifier=entry_id,
        metadata={
            "feed_url": feed_url,
            "entry_id": entry_id,
            "entry_title": entry.get("title", ""),
            "entry_link": entry.get("link", ""),
        },
        title=str(entry.get("title") or ""),
        source_url=str(entry.get("link") or ""),
    )


def _entry_to_blurb(feed_url: str, entry: dict[str, Any]) -> str:
    """Condense an RSS/Atom entry into a text blurb for hypothesis-generator."""
    title = entry.get("title") or "Untitled"
    link = entry.get("link") or ""
    summary = _strip_html(entry.get("summary", ""))[:1500]
    tags = [t.get("term", "") for t in entry.get("tags", []) if t.get("term")]
    techniques = sorted(set(_TECHNIQUE_RE.findall(f"{title}\n{summary}")))
    feed_title = entry.get("feed_title") or _feed_domain(feed_url)

    lines = [f"RSS: {title}", f"Source: {feed_title}"]
    if tags:
        lines.append(f"Tags: {', '.join(tags[:10])}")
    if techniques:
        lines.append(f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}")
    if summary:
        lines.append(f"Summary: {summary}")
    if link:
        lines.append(f"Link: {link}")

    return "\n".join(lines)


def _feed_domain(feed_url: str) -> str:
    return re.sub(r"^https?://(www\.)?", "", feed_url).split("/")[0]
