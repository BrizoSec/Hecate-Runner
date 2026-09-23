"""RssProvider tests. All HTTP is mocked via httpx.MockTransport — no network."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.rss import (
    RssCursorState,
    RssError,
    RssProvider,
    _entry_published,
    _entry_to_blurb,
    _entry_to_cti_item,
    _strip_html,
)
from hecate_runner.orchestrator import has_narrative, is_actionable

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
          <title>{e["title"]}</title>
          <link>{e["link"]}</link>
          <guid>{e.get("guid", e["link"])}</guid>
          <pubDate>{e["pub_date"]}</pubDate>
          <description>{e.get("description", "")}</description>
          {"".join(f"<category>{t}</category>" for t in e.get("tags", []))}
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
        return httpx.Response(
            200, text=_rss_xml(entries), headers={"content-type": "application/rss+xml"}
        )

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
    assert item.title == "Sample Post"
    assert item.source_url == "https://feed-a.example.com/post-1"


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


def test_entry_published_falls_back_to_non_rfc822_date_format(tmp_path: Path) -> None:
    """Regression test: CrowdStrike's blog emits pubDate as
    "Jul 15, 2026 00:00:00-0500" -- no weekday, comma-separated, no space
    before the offset -- which isn't RFC822 and feedparser's own parser
    leaves published_parsed/updated_parsed as None for. _entry_published
    must still recover the real date from the raw string rather than
    treating the entry as dateless."""
    provider = _make_provider(tmp_path, {FEED_A: [_entry(pub_date="Jul 15, 2026 00:00:00-0500")]})
    entries = provider._fetch_entries(FEED_A)
    assert entries[0].get("published_parsed") is None  # confirms feedparser itself can't parse it

    published = _entry_published(entries[0])
    assert published == datetime(2026, 7, 15, 5, 0, 0, tzinfo=UTC)  # -0500 normalized to UTC


def test_entry_published_returns_none_for_truly_unparseable_date() -> None:
    assert _entry_published({"published": "not a date at all"}) is None
    assert _entry_published({}) is None


def test_unparseable_date_does_not_win_oldest_over_a_real_older_date(tmp_path: Path) -> None:
    """Regression test: an entry whose date feedparser AND the strptime
    fallback both fail on used to sort as datetime.min (oldest possible),
    letting it win "oldest wins" against every other feed indefinitely
    regardless of its true age. It must now sort as newest (lowest
    priority) so a real, verifiably-older entry from another feed wins."""
    unparseable = _entry(link="https://feed-a.example.com/no-date", pub_date="not a date at all")
    really_older = _entry(link="https://feed-b.example.com/old", pub_date=_days_ago(10))
    provider = _make_provider(tmp_path, {FEED_A: [unparseable], FEED_B: [really_older]})

    item = provider.next_item()
    assert item is not None
    assert item.identifier == "https://feed-b.example.com/old"


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
    provider = _make_provider(tmp_path, {FEED_A: [_entry()]}, status_codes={FEED_A: 500})
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
    assert cursor.seen_ids[FEED_A] == ["https://feed-a.example.com/post-1"]


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
    assert cursor.seen_ids == {}


def test_cursor_loads_legacy_single_last_seen_id_format(tmp_path: Path) -> None:
    """Back-compat: cursor files written before the seen-set fix stored a
    single 'last_seen_id' string per feed. Loading one must not lose that
    entry's already-routed status."""
    path = tmp_path / "cursor.json"
    path.write_text(json.dumps({"last_seen_id": {FEED_A: "entry-a1"}}))

    cursor = RssCursorState.load(path)
    assert cursor.already_routed(FEED_A, "entry-a1")


def test_previously_routed_entry_is_not_reprocessed_after_a_later_entry_in_same_feed_is_acknowledged(
    tmp_path: Path,
) -> None:
    """Regression: RssCursorState used to store only the single most
    recently acknowledged entry ID per feed. Acknowledging entry B after A
    overwrote A's ID, so A looked unrouted again on the next poll and got
    reprocessed indefinitely -- the exact bug behind duplicate research
    docs being generated for the same article over and over in production."""
    entry_a = _entry(link="https://feed-a.example.com/a", pub_date=_days_ago(5))
    entry_b = _entry(link="https://feed-a.example.com/b", pub_date=_days_ago(1))
    provider = _make_provider(tmp_path, {FEED_A: [entry_a, entry_b]})

    first = provider.next_item()
    assert first is not None
    assert first.identifier == entry_a["link"]
    provider.acknowledge(first)

    second = provider.next_item()
    assert second is not None
    assert second.identifier == entry_b["link"]
    provider.acknowledge(second)

    # Both entries have now been routed; neither should come back, and in
    # particular entry_a must not resurface just because entry_b was
    # acknowledged afterward.
    assert provider.next_item() is None


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
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, text=_rss_xml([])))
    )
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


@pytest.mark.parametrize("placeholder", ["[object Object]", "<p>[object Object]</p>", "undefined"])
def test_placeholder_title_and_summary_are_treated_as_missing(placeholder: str) -> None:
    # Huntress's feed renders every title and description as "[object Object]".
    # Passed through, it read as a narrative Summary and research searched for
    # the literal string (R-0001/H-0001).
    entry = {"title": placeholder, "summary": placeholder, "link": "https://example.com/post"}

    blurb = _entry_to_blurb(FEED_A, entry)

    assert "object Object" not in blurb
    assert "Summary:" not in blurb
    assert not has_narrative(blurb)
    assert not is_actionable(blurb)
    item = _entry_to_cti_item(FEED_A, {**entry, "id": "x"})
    assert item.title == ""
    assert item.metadata["entry_title"] == ""


def test_placeholder_summary_keeps_real_title() -> None:
    blurb = _entry_to_blurb(
        FEED_A, {"title": "Akira affiliates abuse SonicWall VPNs", "summary": "[object Object]"}
    )
    assert "RSS: Akira affiliates abuse SonicWall VPNs" in blurb
    assert "Summary:" not in blurb


def test_strip_html_removes_tags_and_unescapes_entities() -> None:
    assert _strip_html("<p>Adversaries &amp; defenders</p>") == "Adversaries & defenders"


def test_strip_html_handles_empty_input() -> None:
    assert _strip_html("") == ""


# --- Dedup across an unstable GUID -----------------------------------------
#
# CrowdStrike's blog re-issued a different <guid> for an unchanged post on
# successive fetches -- four distinct "?p=NNNNNN" ids for one article, with a
# constant link. Dedup keyed on `id` alone therefore re-routed it once per
# poll, producing four identical hunts and four identical research documents
# from a single article (H-0007/0009/0011/0013). Matching on the link as well
# is what closes that.


def test_same_article_with_a_rotating_guid_routes_only_once(tmp_path: Path) -> None:
    link = "https://feed-a.example.com/patch-tuesday-analysis"
    entries = [_entry(title="Patch Tuesday", link=link, guid="https://feed-a.example.com/?p=1")]
    provider = _make_provider(tmp_path, {FEED_A: entries})

    first = provider.next_item()
    assert first is not None
    provider.acknowledge(first)

    # Same article, brand-new guid on each subsequent fetch.
    for post_id in (2, 3, 4):
        entries[0]["guid"] = f"https://feed-a.example.com/?p={post_id}"
        repeat = provider.next_item()
        assert repeat is None, f"re-routed the same article under guid ?p={post_id}"


def test_a_genuinely_new_article_still_routes(tmp_path: Path) -> None:
    first_entry = _entry(title="First", link="https://feed-a.example.com/first")
    entries = [first_entry]
    provider = _make_provider(tmp_path, {FEED_A: entries})

    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    entries.append(_entry(title="Second", link="https://feed-a.example.com/second"))
    second = provider.next_item()

    assert second is not None
    assert second.metadata["entry_link"] == "https://feed-a.example.com/second"


def test_acknowledge_remembers_both_identifiers(tmp_path: Path) -> None:
    link = "https://feed-a.example.com/post"
    provider = _make_provider(
        tmp_path, {FEED_A: [_entry(link=link, guid="https://feed-a.example.com/?p=99")]}
    )

    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    cursor = RssCursorState.load(provider.cursor_file)
    assert cursor.already_routed(FEED_A, "https://feed-a.example.com/?p=99")
    assert cursor.already_routed(FEED_A, link)


def test_single_identifier_cursor_api_still_works() -> None:
    """advance()/already_routed() keep their single-string form; the plural
    variants are additive."""
    cursor = RssCursorState()
    cursor.advance(FEED_A, "entry-a1")

    assert cursor.already_routed(FEED_A, "entry-a1")
    assert not cursor.already_routed(FEED_A, "entry-a2")
    assert cursor.already_routed_any(FEED_A, ["entry-a2", "entry-a1"])
    assert not cursor.already_routed_any(FEED_A, ["entry-a2", "entry-a3"])


def test_advance_all_ignores_empty_identifiers() -> None:
    cursor = RssCursorState()
    cursor.advance_all(FEED_A, ["real-id", "", "real-id"])

    assert cursor.seen_ids[FEED_A] == ["real-id"]
