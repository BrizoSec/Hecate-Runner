"""RssProvider tests. All HTTP is mocked via httpx.MockTransport — no network."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from sec7669.cti.base import CTIItem
from sec7669.cti.rss import RssCursorState, RssError, RssProvider, _entry_to_blurb, _strip_html

FEED_A = "https://feed-a.example.com/rss/"
FEED_B = "https://feed-b.example.com/rss/"


def _rfc822(dt: datetime) -> str:
    """Format a datetime as an RFC 822 pubDate string, as real feeds do."""
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _days_ago(days: int) -> str:
    """RFC 822 pubDate relative to now — avoids hardcoded dates that age out
    of any max_entry_age_days cutoff as real time moves forward."""
    return _rfc822(datetime.now(UTC) - timedelta(days=days))


def _rss_xml(entries: list[dict[str, str]]) -> str:
    items = "\n".join(
        f"""
        <item>
          <title>{e['title']}</title>
          <link>{e['link']}</link>
          <guid>{e.get('guid', e['link'])}</guid>
          <pubDate>{e['pub_date']}</pubDate>
          <description>{e.get('description', '')}</description>
          {"".join(f'<category>{t}</category>' for t in e.get('tags', []))}
        </item>
        """
        for e in entries
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Test Feed</title>{items}</channel></rss>"""


def _entry(
    title: str = "Sample Post",
    link: str = "https://feed-a.example.com/post-1",
    guid: str | None = None,
    pub_date: str | None = None,
    description: str = "<p>Adversaries dump LSASS via comsvcs.dll.</p>",
    tags: list[str] | None = None,
) -> dict[str, str]:
    return {
        "title": title,
        "link": link,
        "guid": guid or link,
        "pub_date": pub_date or _days_ago(1),
        "description": description,
        "tags": tags or [],
    }


def _make_provider(
    tmp_path: Path,
    feeds: dict[str, list[dict[str, str]]],
    *,
    max_entry_age_days: int = 30,
    on_request: Callable[[httpx.Request], None] | None = None,
    status_codes: dict[str, int] | None = None,
) -> RssProvider:
    status_codes = status_codes or {}

    def handler(request: httpx.Request) -> httpx.Response:
        if on_request:
            on_request(request)
        url = str(request.url)
        code = status_codes.get(url, 200)
        if code != 200:
            return httpx.Response(code, text="error")
        entries = feeds.get(url, [])
        return httpx.Response(200, text=_rss_xml(entries), headers={"content-type": "application/rss+xml"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return RssProvider(
        feed_urls=list(feeds.keys()),
        cursor_file=tmp_path / "rss_cursor.json",
        max_entry_age_days=max_entry_age_days,
        client=client,
    )


# --- Construction --------------------------------------------------------------


def test_requires_at_least_one_feed_url(tmp_path: Path) -> None:
    with pytest.raises(RssError, match="At least one feed URL"):
        RssProvider(feed_urls=[], cursor_file=tmp_path / "cursor.json")


# --- next_item / filtering -------------------------------------------------------


def test_next_item_returns_none_when_no_entries(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, {FEED_A: []})
    assert provider.next_item() is None


def test_next_item_returns_entry(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, {FEED_A: [_entry()]})
    item = provider.next_item()
    assert item is not None
    assert item.source == "rss"
    assert item.identifier == "https://feed-a.example.com/post-1"
    assert "Sample Post" in item.content
    assert item.metadata["feed_url"] == FEED_A


def test_filters_out_stale_entries(tmp_path: Path) -> None:
    old_entry = _entry(pub_date=_days_ago(3650))  # ~10 years back — always stale
    provider = _make_provider(tmp_path, {FEED_A: [old_entry]}, max_entry_age_days=30)
    assert provider.next_item() is None


def test_picks_oldest_unrouted_candidate_across_feeds(tmp_path: Path) -> None:
    # Both well within the default 30-day cutoff, but clearly ordered.
    older = _entry(link="https://feed-a.example.com/old", pub_date=_days_ago(5))
    newer = _entry(link="https://feed-b.example.com/new", pub_date=_days_ago(1))
    provider = _make_provider(tmp_path, {FEED_A: [older], FEED_B: [newer]})

    item = provider.next_item()
    assert item is not None
    assert item.identifier == "https://feed-a.example.com/old"


def test_one_feed_failing_does_not_block_others(tmp_path: Path) -> None:
    good_entry = _entry(link="https://feed-b.example.com/good")
    provider = _make_provider(
        tmp_path,
        {FEED_A: [_entry()], FEED_B: [good_entry]},
        status_codes={FEED_A: 500},
    )
    item = provider.next_item()
    assert item is not None
    assert item.identifier == "https://feed-b.example.com/good"


def test_all_feeds_failing_returns_none_not_raise(tmp_path: Path) -> None:
    provider = _make_provider(
        tmp_path, {FEED_A: [_entry()]}, status_codes={FEED_A: 500}
    )
    assert provider.next_item() is None


def test_entry_without_id_or_link_is_skipped(tmp_path: Path) -> None:
    # No link/guid at all -- constructed manually since _entry() always sets one.
    xml = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
    <item><title>No link here</title><pubDate>{_days_ago(1)}</pubDate></item>
    </channel></rss>"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=xml)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = RssProvider(feed_urls=[FEED_A], cursor_file=tmp_path / "cursor.json", client=client)
    assert provider.next_item() is None


# --- acknowledge / cursor persistence --------------------------------------------


def test_acknowledge_advances_and_persists_cursor(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, {FEED_A: [_entry()]})
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    cursor = RssCursorState.load(provider.cursor_file)
    assert cursor.last_seen_id[FEED_A] == "https://feed-a.example.com/post-1"


def test_acknowledged_entry_is_not_returned_again(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, {FEED_A: [_entry()]})
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    assert provider.next_item() is None


def test_acknowledge_missing_metadata_does_not_raise(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, {FEED_A: []})
    provider.acknowledge(CTIItem(content="stray item"))  # no-op, no crash


def test_cursor_state_corrupt_file_resets(tmp_path: Path) -> None:
    path = tmp_path / "cursor.json"
    path.write_text("{not valid json")
    cursor = RssCursorState.load(path)
    assert cursor.last_seen_id == {}


def test_cursor_tracks_multiple_feeds_independently(tmp_path: Path) -> None:
    cursor = RssCursorState()
    cursor.advance(FEED_A, "entry-a1")
    cursor.advance(FEED_B, "entry-b1")
    assert cursor.already_routed(FEED_A, "entry-a1")
    assert not cursor.already_routed(FEED_B, "entry-a1")
    assert cursor.already_routed(FEED_B, "entry-b1")


# --- close() -----------------------------------------------------------------------


def test_close_closes_owned_client(tmp_path: Path) -> None:
    provider = RssProvider(feed_urls=[FEED_A], cursor_file=tmp_path / "cursor.json")
    provider.close()
    assert provider._client.is_closed


def test_close_does_not_close_injected_client(tmp_path: Path) -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, text=_rss_xml([]))))
    provider = RssProvider(feed_urls=[FEED_A], cursor_file=tmp_path / "cursor.json", client=client)
    provider.close()
    assert not client.is_closed
    client.close()


# --- blurb rendering / HTML stripping -----------------------------------------------


def test_blurb_includes_key_fields() -> None:
    entry_data = _entry(
        title="LSASS dumping via comsvcs.dll",
        description="<p>Adversaries observed using T1003.001 to dump credentials.</p>",
        tags=["ransomware", "credential-access"],
    )
    import feedparser

    parsed = feedparser.parse(_rss_xml([entry_data]))
    blurb = _entry_to_blurb(FEED_A, parsed.entries[0])

    assert "LSASS dumping via comsvcs.dll" in blurb
    assert "feed-a.example.com" in blurb
    assert "ransomware" in blurb
    assert "T1003.001" in blurb
    assert "Adversaries observed using" in blurb
    assert "https://feed-a.example.com/post-1" in blurb


def test_blurb_handles_sparse_entry() -> None:
    blurb = _entry_to_blurb(FEED_A, {})
    assert "Untitled" in blurb


def test_strip_html_removes_tags_and_unescapes_entities() -> None:
    assert _strip_html("<p>Adversaries &amp; defenders</p>") == "Adversaries & defenders"


def test_strip_html_handles_empty_input() -> None:
    assert _strip_html("") == ""
