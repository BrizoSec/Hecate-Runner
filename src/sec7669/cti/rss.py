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

Cursor state (last-seen entry ID per feed URL) is persisted to disk, same
shape and reasoning as OtxCursorState: repeat polls don't re-ingest an
entry, and a crash mid-cycle doesn't lose position. Each feed's failure
(network error, malformed XML, blocked request) is isolated — one broken
feed doesn't stop entries from other configured feeds being considered.
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import feedparser
import httpx

from sec7669.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

REQUEST_USER_AGENT = "sec7669-cti-poller/1.0 (+https://github.com/BrizoSec/sec7669)"

# Same pattern used in orchestrator.derive_research_topic — kept separate
# rather than imported to avoid a cti/ -> orchestrator dependency cycle.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_HTML_TAG_RE = re.compile(r"<[^>]+>")


class RssError(RuntimeError):
    """Raised when an RSS provider operation fails outright (not per-feed)."""


@dataclass
class RssCursorState:
    """Per-feed last-seen entry ID, persisted between polls."""

    last_seen_id: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> RssCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text())
            return cls(last_seen_id=dict(data.get("last_seen_id", {})))
        except (json.JSONDecodeError, TypeError) as exc:
            log.warning("RSS cursor file %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"last_seen_id": self.last_seen_id}, indent=2))

    def already_routed(self, feed_url: str, entry_id: str) -> bool:
        return self.last_seen_id.get(feed_url) == entry_id

    def advance(self, feed_url: str, entry_id: str) -> None:
        self.last_seen_id[feed_url] = entry_id


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
            timeout=request_timeout_sec, headers={"User-Agent": REQUEST_USER_AGENT}, follow_redirects=True
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
                entry_id = _entry_id(entry)
                if not entry_id or cursor.already_routed(feed_url, entry_id):
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
        # feed happens to be checked first.
        candidates.sort(key=lambda pair: _entry_published(pair[1]) or datetime.min.replace(tzinfo=UTC))
        feed_url, entry = candidates[0]
        return _entry_to_cti_item(feed_url, entry)

    def acknowledge(self, item: CTIItem) -> None:
        feed_url = item.metadata.get("feed_url")
        entry_id = item.metadata.get("entry_id")
        if not feed_url or not entry_id:
            log.warning("Cannot advance RSS cursor: item missing feed metadata (%r)", item)
            return
        cursor = RssCursorState.load(self.cursor_file)
        cursor.advance(feed_url, entry_id)
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


def _entry_published(entry: dict[str, Any]) -> datetime | None:
    parsed_time = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed_time:
        return None
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
        lines.append(f"MITRE ATT&CK Techniques: {', '.join(techniques)}")
    if summary:
        lines.append(f"Summary: {summary}")
    if link:
        lines.append(f"Link: {link}")

    return "\n".join(lines)


def _feed_domain(feed_url: str) -> str:
    return re.sub(r"^https?://(www\.)?", "", feed_url).split("/")[0]
