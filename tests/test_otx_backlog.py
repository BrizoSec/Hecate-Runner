"""OTX backlog: find the true oldest pulse, and park rather than lose expired ones.

Page 1 of the subscribed feed is the *newest* 20. Selecting "oldest on page 1"
meant that once more than 20 were waiting, older pulses slid off the page and
the cursor then advanced past them for good -- 23 high-signal pulses since
15 Sep, including Hangro (47 IOCs), vanished without a record.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.otx import OtxCursorState, OtxProvider
from hecate_runner.cti_triage import triage


def _ts(days_ago: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f")


def _paged_provider(
    tmp_path: Path, pulses_newest_first: list[dict[str, Any]], *, max_pages: int = 10
) -> tuple[OtxProvider, list[int]]:
    """OTX pages newest first, 20 per page, with a `next` link while more remain."""
    pages_requested: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        pages_requested.append(page)
        chunk = pulses_newest_first[(page - 1) * 20 : page * 20]
        more = page * 20 < len(pulses_newest_first)
        return httpx.Response(
            200,
            json={
                "count": len(pulses_newest_first),
                "results": chunk,
                "next": f"https://otx/?page={page + 1}" if more else None,
            },
        )

    provider = OtxProvider(
        api_key="k",
        cursor_file=tmp_path / "cursor.json",
        max_pages=max_pages,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    return provider, pages_requested


def _backlog(sample: dict[str, Any], n: int) -> list[dict[str, Any]]:
    """n high-signal pulses, newest first; pN was modified N hours ago."""
    return [
        dict(sample, id=f"p{i}", name=f"Pulse {i}", created=_ts(i / 24), modified=_ts(i / 24))
        for i in range(1, n + 1)
    ]


def _cursor_at(tmp_path: Path, days_ago: float) -> None:
    OtxCursorState(last_modified=_ts(days_ago), seen_ids_at_cursor=[]).save(
        tmp_path / "cursor.json"
    )


def test_the_oldest_pulse_is_found_even_beyond_page_one(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    """25 waiting, newest first. Reading page 1 alone offered p20, and
    p21..p25 were later skipped for good."""
    provider, pages = _paged_provider(tmp_path, _backlog(sample_otx_pulse, 25))
    item = provider.next_item()
    assert item is not None
    assert item.identifier == "p25"
    assert pages == [1, 2]
    assert item.metadata["backlog"] == 25


def test_paging_stops_at_the_bound_and_says_so(
    tmp_path: Path, sample_otx_pulse: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    provider, pages = _paged_provider(tmp_path, _backlog(sample_otx_pulse, 60), max_pages=2)
    item = provider.next_item()
    assert pages == [1, 2]
    assert item is not None and item.identifier == "p40"
    assert "backlog exceeds 2 pages" in caplog.text


def test_a_pulse_that_expired_while_waiting_is_handed_over_to_be_parked(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    _cursor_at(tmp_path, 40)
    expired = dict(sample_otx_pulse, id="old", created=_ts(35), modified=_ts(34))
    fresh = dict(sample_otx_pulse, id="new", created=_ts(2), modified=_ts(2))
    provider, _ = _paged_provider(tmp_path, [fresh, expired])

    item = provider.next_item()

    assert item is not None and item.identifier == "old"
    assert "freshness limit" in item.metadata["aged_out"]
    assert item.metadata["backlog"] == 1  # the fresh one is still waiting
    verdict = triage(item)
    assert verdict.park and verdict.reason.startswith("aged out:")


def test_an_ancient_pulse_republished_today_was_never_waiting(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    _cursor_at(tmp_path, 5)
    republished = dict(sample_otx_pulse, id="ancient", created=_ts(400), modified=_ts(1))
    provider, _ = _paged_provider(tmp_path, [republished])
    assert provider.next_item() is None


def test_a_fresh_install_has_no_backlog_to_age_out(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    expired = dict(sample_otx_pulse, id="old", created=_ts(35), modified=_ts(34))
    provider, _ = _paged_provider(tmp_path, [expired])
    assert provider.next_item() is None


def test_triage_ignores_items_without_the_flag() -> None:
    assert triage(CTIItem(content="x", metadata={})).park is False
