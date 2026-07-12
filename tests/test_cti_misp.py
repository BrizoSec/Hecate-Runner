"""MispProvider tests. All HTTP is mocked via httpx.MockTransport — no network.

Fixture shapes mirror MISP's own bundled test data (verified live against
misp-core's /var/www/MISP/tests/event.json and
app/files/misp-galaxy/clusters/mitre-attack-pattern.json), not guessed.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from sec7669.cti.base import CTIItem
from sec7669.cti.misp import MispCursorState, MispError, MispProvider, _event_to_blurb


def _epoch_days_ago(days: int) -> str:
    """Unix epoch seconds relative to now, as a string (matches MISP's timestamp field).

    Avoids hardcoded epoch values that age out of any max_event_age_days
    cutoff as real time moves forward -- the same class of bug this file
    hit once already before being caught by running the suite for real.
    """
    return str(int((datetime.now(UTC) - timedelta(days=days)).timestamp()))


_DEFAULT_TIMESTAMP = _epoch_days_ago(1)


def _sample_event(**overrides: Any) -> dict[str, Any]:
    event = {
        "id": "750",
        "uuid": "54884656-2da8-4625-bf07-43ef950d210b",
        "info": "OSINT - LSASS memory dumping observed",
        "date": (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d"),
        "threat_level_id": "1",
        "analysis": "2",
        "published": True,
        "timestamp": _DEFAULT_TIMESTAMP,
        "publish_timestamp": _DEFAULT_TIMESTAMP,
        "Org": {"id": "2", "name": "CIRCL", "uuid": "org-uuid"},
        "Orgc": {"id": "2", "name": "CIRCL", "uuid": "org-uuid"},
        "Tag": [{"id": "1", "name": "tlp:white", "colour": "#ffffff", "exportable": True}],
        "Galaxy": [
            {
                "type": "mitre-attack-pattern",
                "name": "Attack Pattern",
                "GalaxyCluster": [
                    {
                        "tag_name": 'misp-galaxy:mitre-attack-pattern="LSASS Memory - T1003.001"',
                        "value": "LSASS Memory - T1003.001",
                        "meta": {"external_id": ["T1003.001"]},
                    }
                ],
            }
        ],
        "Attribute": [
            {"type": "sha256", "category": "Payload delivery", "value": "a" * 64},
            {"type": "ip-dst", "category": "Network activity", "value": "1.2.3.4"},
        ],
    }
    event.update(overrides)
    return event


def _make_provider(
    tmp_path: Path,
    events: list[dict[str, Any]],
    *,
    status_code: int = 200,
    max_event_age_days: int = 30,
    on_request: Callable[[httpx.Request], None] | None = None,
) -> MispProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        if on_request:
            on_request(request)
        if status_code != 200:
            return httpx.Response(status_code, text="error")
        return httpx.Response(200, json={"response": [{"Event": e} for e in events]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return MispProvider(
        base_url="https://misp.example.com",
        api_key="test-key",
        cursor_file=tmp_path / "cursor.json",
        max_event_age_days=max_event_age_days,
        client=client,
    )


# --- Construction --------------------------------------------------------------


def test_requires_base_url(tmp_path: Path) -> None:
    with pytest.raises(MispError, match="base URL"):
        MispProvider(base_url="", api_key="key", cursor_file=tmp_path / "cursor.json")


def test_requires_api_key(tmp_path: Path) -> None:
    with pytest.raises(MispError, match="MISP_API_KEY"):
        MispProvider(base_url="https://misp.example.com", api_key="", cursor_file=tmp_path / "cursor.json")


# --- next_item / filtering ----------------------------------------------------


def test_next_item_returns_none_when_no_events(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [])
    assert provider.next_item() is None


def test_next_item_returns_high_signal_event(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [_sample_event()])
    item = provider.next_item()
    assert item is not None
    assert item.source == "misp"
    assert item.identifier == "54884656-2da8-4625-bf07-43ef950d210b"
    assert "LSASS memory dumping" in item.content
    assert item.metadata["event_uuid"] == "54884656-2da8-4625-bf07-43ef950d210b"


def test_filters_out_unpublished_events(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [_sample_event(published=False)])
    assert provider.next_item() is None


def test_filters_out_tlp_red(tmp_path: Path) -> None:
    event = _sample_event(Tag=[{"id": "1", "name": "tlp:red"}])
    provider = _make_provider(tmp_path, [event])
    assert provider.next_item() is None


def test_filters_out_tlp_amber(tmp_path: Path) -> None:
    event = _sample_event(Tag=[{"id": "1", "name": "tlp:amber"}])
    provider = _make_provider(tmp_path, [event])
    assert provider.next_item() is None


def test_missing_tlp_tag_defaults_to_safe(tmp_path: Path) -> None:
    event = _sample_event(Tag=[])
    provider = _make_provider(tmp_path, [event])
    assert provider.next_item() is not None


def test_tlp_clear_is_high_signal(tmp_path: Path) -> None:
    event = _sample_event(Tag=[{"id": "1", "name": "tlp:clear"}])
    provider = _make_provider(tmp_path, [event])
    assert provider.next_item() is not None


def test_event_without_galaxy_is_still_high_signal(tmp_path: Path) -> None:
    # Unlike OTX (which requires attack_ids), MISP events don't need a
    # Galaxy/technique mapping to be considered high signal -- the source
    # instance's own curation is the primary filter, same reasoning as RSS.
    event = _sample_event(Galaxy=[])
    provider = _make_provider(tmp_path, [event])
    item = provider.next_item()
    assert item is not None
    assert "MITRE ATT&CK Techniques" not in item.content


def test_filters_out_unnamed_events(tmp_path: Path) -> None:
    event = _sample_event(info="  ")
    provider = _make_provider(tmp_path, [event])
    assert provider.next_item() is None


def test_filters_out_stale_events(tmp_path: Path) -> None:
    event = _sample_event(date="2020-01-01", timestamp=_epoch_days_ago(3650))  # ~10 years back — always stale
    provider = _make_provider(tmp_path, [event], max_event_age_days=30)
    assert provider.next_item() is None


def test_picks_oldest_unrouted_candidate(tmp_path: Path) -> None:
    # Both well within the default 30-day cutoff, but clearly ordered.
    older = _sample_event(uuid="uuid-old", timestamp=_epoch_days_ago(5))
    newer = _sample_event(uuid="uuid-new", timestamp=_epoch_days_ago(1))
    provider = _make_provider(tmp_path, [newer, older])
    item = provider.next_item()
    assert item is not None
    assert item.identifier == "uuid-old"


def test_sends_auth_header_and_published_filter(tmp_path: Path) -> None:
    seen_requests: list[httpx.Request] = []
    provider = _make_provider(tmp_path, [_sample_event()], on_request=seen_requests.append)
    provider.next_item()

    assert len(seen_requests) == 1
    assert seen_requests[0].headers["authorization"] == "test-key"
    import json as jsonlib

    body = jsonlib.loads(seen_requests[0].content)
    assert body["published"] == 1
    assert "timestamp" not in body  # first-ever poll, no cursor yet

    cursor = MispCursorState(last_timestamp="1751241600")
    cursor.save(provider.cursor_file)
    provider.next_item()
    body2 = jsonlib.loads(seen_requests[1].content)
    assert body2["timestamp"] == "1751241600"


# --- acknowledge / cursor persistence -----------------------------------------


def test_acknowledge_advances_and_persists_cursor(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [_sample_event()])
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    cursor = MispCursorState.load(provider.cursor_file)
    assert cursor.last_timestamp == _DEFAULT_TIMESTAMP
    assert cursor.seen_ids_at_cursor == ["54884656-2da8-4625-bf07-43ef950d210b"]


def test_acknowledged_event_is_not_returned_again(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [_sample_event()])
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)

    assert provider.next_item() is None


def test_acknowledge_missing_metadata_does_not_raise(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [])
    provider.acknowledge(CTIItem(content="stray item"))  # no-op, no crash


def test_cursor_state_corrupt_file_resets(tmp_path: Path) -> None:
    path = tmp_path / "cursor.json"
    path.write_text("{not valid json")
    cursor = MispCursorState.load(path)
    assert cursor.last_timestamp == ""
    assert cursor.seen_ids_at_cursor == []


# --- HTTP error handling -------------------------------------------------------


def test_403_raises_misp_error(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [_sample_event()], status_code=403)
    with pytest.raises(MispError, match="authentication"):
        provider.next_item()


def test_other_error_status_raises_misp_error(tmp_path: Path) -> None:
    provider = _make_provider(tmp_path, [_sample_event()], status_code=500)
    with pytest.raises(MispError, match="500"):
        provider.next_item()


def test_transport_error_raises_misp_error(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = MispProvider(
        base_url="https://misp.example.com", api_key="test-key", cursor_file=tmp_path / "cursor.json", client=client
    )
    with pytest.raises(MispError, match="MISP request failed"):
        provider.next_item()


# --- close() -------------------------------------------------------------------


def test_close_closes_owned_client(tmp_path: Path) -> None:
    provider = MispProvider(base_url="https://misp.example.com", api_key="test-key", cursor_file=tmp_path / "cursor.json")
    provider.close()
    assert provider._client.is_closed


def test_close_does_not_close_injected_client(tmp_path: Path) -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"response": []})))
    provider = MispProvider(
        base_url="https://misp.example.com", api_key="test-key", cursor_file=tmp_path / "cursor.json", client=client
    )
    provider.close()
    assert not client.is_closed
    client.close()


# --- blurb rendering -----------------------------------------------------------


def test_blurb_includes_key_fields() -> None:
    blurb = _event_to_blurb("https://misp.example.com", _sample_event())
    assert "LSASS memory dumping" in blurb
    assert "Org: CIRCL" in blurb
    assert "Threat Level: High" in blurb
    assert "TLP: white" in blurb
    assert "T1003.001" in blurb
    assert "sha256 (1)" in blurb
    assert "ip-dst (1)" in blurb
    assert "https://misp.example.com/events/view/750" in blurb


def test_blurb_excludes_tlp_and_galaxy_tags_from_tags_line() -> None:
    event = _sample_event(
        Tag=[
            {"name": "tlp:white"},
            {"name": "misp-galaxy:mitre-attack-pattern=\"LSASS Memory - T1003.001\""},
            {"name": "ransomware"},
        ]
    )
    blurb = _event_to_blurb("https://misp.example.com", event)
    tags_line = next(line for line in blurb.splitlines() if line.startswith("Tags:"))
    assert tags_line == "Tags: ransomware"


def test_blurb_handles_sparse_event() -> None:
    blurb = _event_to_blurb("https://misp.example.com", {})
    assert "Untitled event" in blurb
    assert "Org: Unknown" in blurb
