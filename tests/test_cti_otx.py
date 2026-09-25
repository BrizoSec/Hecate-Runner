"""OtxProvider tests. All HTTP is mocked via httpx.MockTransport — no network."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.otx import (
    OtxCursorState,
    OtxError,
    OtxProvider,
    _pulse_to_blurb,
    _pulse_to_cti_item,
)


def _make_provider(
    tmp_path: Path,
    pulses: list[dict[str, Any]],
    *,
    status_code: int = 200,
    max_pulse_age_days: int = 30,
    on_request: Callable[[httpx.Request], None] | None = None,
) -> OtxProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        if on_request:
            on_request(request)
        if status_code != 200:
            return httpx.Response(status_code, text="error")
        return httpx.Response(200, json={"count": len(pulses), "results": pulses})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OtxProvider(
        api_key="test-key",
        cursor_file=tmp_path / "cursor.json",
        max_pulse_age_days=max_pulse_age_days,
        client=client,
    )


# --- Construction ------------------------------------------------------------


def test_requires_api_key(tmp_path: Path) -> None:
    with pytest.raises(OtxError, match="OTX_API_KEY"):
        OtxProvider(api_key="", cursor_file=tmp_path / "cursor.json")


# --- next_item / filtering ----------------------------------------------------


def test_next_item_returns_none_when_no_pulses(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [])
    assert provider.next_item() is None


def test_next_item_returns_high_signal_pulse(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    provider = _make_provider(tmp_path, [sample_otx_pulse])
    item = provider.next_item()
    assert item is not None
    assert item.source == "otx"
    assert item.identifier == "pulse-1"
    assert "APT41" in item.content
    assert item.metadata["pulse_id"] == "pulse-1"


def test_filters_out_non_white_green_tlp(tmp_path: Path, sample_otx_pulse: dict[str, Any]) -> None:
    sample_otx_pulse["TLP"] = "red"
    provider = _make_provider(tmp_path, [sample_otx_pulse])
    assert provider.next_item() is None


def test_filters_out_pulses_without_attack_ids(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    sample_otx_pulse["attack_ids"] = []
    provider = _make_provider(tmp_path, [sample_otx_pulse])
    assert provider.next_item() is None


def test_filters_out_stale_pulses(tmp_path: Path, sample_otx_pulse: dict[str, Any]) -> None:
    sample_otx_pulse["created"] = "2020-01-01T00:00:00.000000"
    sample_otx_pulse["modified"] = "2020-01-01T00:00:00.000000"
    provider = _make_provider(tmp_path, [sample_otx_pulse], max_pulse_age_days=30)
    assert provider.next_item() is None


def test_filters_out_unnamed_pulses(tmp_path: Path, sample_otx_pulse: dict[str, Any]) -> None:
    sample_otx_pulse["name"] = "  "
    provider = _make_provider(tmp_path, [sample_otx_pulse])
    assert provider.next_item() is None


def test_picks_oldest_unrouted_candidate(tmp_path: Path, sample_otx_pulse: dict[str, Any]) -> None:
    older = dict(sample_otx_pulse, id="pulse-old", modified="2026-06-01T00:00:00.000000")
    newer = dict(sample_otx_pulse, id="pulse-new", modified="2026-07-01T00:00:00.000000")
    provider = _make_provider(tmp_path, [newer, older])
    item = provider.next_item()
    assert item is not None
    assert item.identifier == "pulse-old"


def test_missing_modified_does_not_win_oldest_over_a_real_older_pulse(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    """Regression test: a pulse with a missing/unparseable `modified` value
    used to sort via the raw string `p.get("modified", "")`, defaulting to
    "" -- which sorts lexicographically before any real ISO8601 date string,
    i.e. "oldest possible" -- so it would always win "oldest wins" against
    every pulse with a real, later `modified` value, regardless of true age.
    Must now sort as newest (lowest priority) so a real, verifiably-older
    pulse wins instead."""
    no_modified = dict(sample_otx_pulse, id="pulse-no-modified", modified="")
    really_older = dict(sample_otx_pulse, id="pulse-old", modified="2026-06-01T00:00:00.000000")
    provider = _make_provider(tmp_path, [no_modified, really_older])

    item = provider.next_item()
    assert item is not None
    assert item.identifier == "pulse-old"


def test_sends_api_key_header_and_modified_since(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    seen_requests: list[httpx.Request] = []
    provider = _make_provider(tmp_path, [sample_otx_pulse], on_request=seen_requests.append)
    provider.next_item()
    assert len(seen_requests) == 1
    assert seen_requests[0].headers["x-otx-api-key"] == "test-key"
    assert "modified_since" not in seen_requests[0].url.params  # first-ever poll

    cursor = OtxCursorState(last_modified="2026-01-01T00:00:00.000000")
    cursor.save(provider.cursor_file)
    provider.next_item()
    assert seen_requests[1].url.params["modified_since"] == "2026-01-01T00:00:00.000000"


# --- acknowledge / cursor persistence -----------------------------------------


def test_acknowledge_advances_and_persists_cursor(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    provider = _make_provider(tmp_path, [sample_otx_pulse])
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    cursor = OtxCursorState.load(provider.cursor_file)
    assert cursor.last_modified == sample_otx_pulse["modified"]
    assert cursor.seen_ids_at_cursor == ["pulse-1"]


def test_acknowledged_pulse_is_not_returned_again(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    provider = _make_provider(tmp_path, [sample_otx_pulse])
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    # Same fixed response returned by the mock server (as a real API would if
    # modified_since filtering happened server-side) — cursor dedup must catch it.
    assert provider.next_item() is None


def test_acknowledge_missing_metadata_does_not_raise(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [])
    provider.acknowledge(CTIItem(content="stray item"))  # no-op, no crash


def test_pulse_to_cti_item_extracts_clean_title_and_source_url(
    sample_otx_pulse: dict[str, Any],
) -> None:
    item = _pulse_to_cti_item(sample_otx_pulse)
    assert item.title == "APT41 credential access campaign"
    assert item.source_url == "https://example.com/report"


def test_pulse_to_cti_item_source_url_empty_without_references(
    sample_otx_pulse: dict[str, Any],
) -> None:
    sample_otx_pulse["references"] = []
    item = _pulse_to_cti_item(sample_otx_pulse)
    assert item.source_url == ""


def test_cursor_state_corrupt_file_resets(tmp_path: Path) -> None:
    path = tmp_path / "cursor.json"
    path.write_text("{not valid json")
    cursor = OtxCursorState.load(path)
    assert cursor.last_modified == ""
    assert cursor.seen_ids_at_cursor == []


def test_advance_ignores_a_stale_older_modified_time() -> None:
    """Regression test: advance() used to unconditionally overwrite
    last_modified with whatever it was called with, no matter its value. A
    stale/late advance() call (e.g. from an overlapping poll acknowledging
    an older pulse after a newer one already advanced the cursor) used to
    regress the cursor backward, making already-routed pulses look unrouted
    again and get re-drafted under a new hunt ID."""
    cursor = OtxCursorState(
        last_modified="2026-06-01T00:00:00.000000", seen_ids_at_cursor=["pulse-newer"]
    )

    cursor.advance("2026-05-01T00:00:00.000000", "pulse-older-stale")

    assert cursor.last_modified == "2026-06-01T00:00:00.000000"
    assert cursor.seen_ids_at_cursor == ["pulse-newer"]


def test_advance_still_moves_forward_normally() -> None:
    cursor = OtxCursorState(
        last_modified="2026-06-01T00:00:00.000000", seen_ids_at_cursor=["pulse-old"]
    )

    cursor.advance("2026-07-01T00:00:00.000000", "pulse-new")

    assert cursor.last_modified == "2026-07-01T00:00:00.000000"
    assert cursor.seen_ids_at_cursor == ["pulse-new"]


# --- HTTP error handling -------------------------------------------------------


def test_401_raises_otx_error(tmp_path: Path, sample_otx_pulse: dict[str, Any]) -> None:
    provider = _make_provider(tmp_path, [sample_otx_pulse], status_code=401)
    with pytest.raises(OtxError, match="authentication"):
        provider.next_item()


def test_429_raises_otx_error(tmp_path: Path, sample_otx_pulse: dict[str, Any]) -> None:
    provider = _make_provider(tmp_path, [sample_otx_pulse], status_code=429)
    with pytest.raises(OtxError, match="rate limit"):
        provider.next_item()


def test_other_error_status_raises_otx_error(
    tmp_path: Path, sample_otx_pulse: dict[str, Any]
) -> None:
    provider = _make_provider(tmp_path, [sample_otx_pulse], status_code=500)
    with pytest.raises(OtxError, match="500"):
        provider.next_item()


def test_transport_error_raises_otx_error(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = OtxProvider(api_key="test-key", cursor_file=tmp_path / "cursor.json", client=client)
    with pytest.raises(OtxError, match="OTX request failed"):
        provider.next_item()


# --- close() -------------------------------------------------------------------


def test_close_closes_owned_client(tmp_path: Path) -> None:
    provider = OtxProvider(api_key="test-key", cursor_file=tmp_path / "cursor.json")
    provider.close()
    assert provider._client.is_closed


def test_close_does_not_close_injected_client(tmp_path: Path) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"results": []}))
    )
    provider = OtxProvider(api_key="test-key", cursor_file=tmp_path / "cursor.json", client=client)
    provider.close()
    assert not client.is_closed
    client.close()


# --- blurb rendering -----------------------------------------------------------


def test_pulse_to_blurb_includes_key_fields(sample_otx_pulse: dict[str, Any]) -> None:
    blurb = _pulse_to_blurb(sample_otx_pulse)
    assert "APT41 credential access campaign" in blurb
    assert "Adversary/Attribution: APT41" in blurb
    assert "T1003.001" in blurb
    assert "FileHash-SHA256 (1)" in blurb
    assert "IPv4 (1)" in blurb
    assert "https://example.com/report" in blurb


def test_pulse_to_blurb_handles_sparse_pulse() -> None:
    blurb = _pulse_to_blurb({"id": "1"})
    assert "Untitled pulse" in blurb
    assert "Unknown" in blurb


def test_indicator_map_groups_observable_values_by_type() -> None:
    from hecate_runner.cti.otx import _indicator_map

    pulse = {
        "indicators": [
            {"type": "domain", "indicator": "evil.example"},
            {"type": "IPv4", "indicator": "10.0.0.1"},
            {"type": "FileHash-SHA256", "indicator": "a" * 64},
            # A CVE names a vulnerability, not something telemetry contains.
            {"type": "CVE", "indicator": "CVE-2026-1234"},
        ]
    }
    assert _indicator_map(pulse) == {
        "domain": ["evil.example"],
        "IPv4": ["10.0.0.1"],
        "FileHash-SHA256": ["a" * 64],
    }


def test_indicator_map_skips_bulk_feed_pulses() -> None:
    """Hundreds of indicators describe a feed, not tradecraft."""
    from hecate_runner.cti.otx import _indicator_map

    pulse = {"indicators": [{"type": "domain", "indicator": f"d{i}.example"} for i in range(500)]}
    assert _indicator_map(pulse) == {}


def test_indicator_map_keeps_a_curated_report_past_forty_indicators() -> None:
    from hecate_runner.cti.otx import _indicator_map

    pulse = {
        "indicators": [{"type": "IPv4", "indicator": f"10.0.0.{i}"} for i in range(30)]
        + [{"type": "domain", "indicator": f"d{i}.example"} for i in range(12)]
    }
    grouped = _indicator_map(pulse)
    assert len(grouped["IPv4"]) == 10
    assert len(grouped["domain"]) == 10
