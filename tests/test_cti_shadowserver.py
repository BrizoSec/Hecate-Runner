"""Tests for Shadowserver Foundation CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.shadowserver import (
    ShadowserverCursorState,
    ShadowserverProvider,
)

SAMPLE_SHADOWSERVER_RESPONSE = [
    {
        "id": "shadowserver-event-999",
        "ip": "203.0.113.45",
        "port": 8080,
        "tag": "c2-sinkhole",
        "family": "CobaltStrike",
        "asn": 64512,
        "asn_name": "Test AS",
        "city": "Amsterdam",
        "country": "NL",
    }
]


def test_shadowserver_cursor_state(tmp_path: Path) -> None:
    cursor_file = tmp_path / "shadowserver_cursor.json"
    cursor = ShadowserverCursorState.load(cursor_file)
    assert not cursor.already_seen("shadowserver-event-999")

    cursor.advance("shadowserver-event-999")
    cursor.save(cursor_file)

    loaded = ShadowserverCursorState.load(cursor_file)
    assert loaded.already_seen("shadowserver-event-999")
    assert not loaded.already_seen("shadowserver-event-1000")


def test_shadowserver_unconfigured_skips(tmp_path: Path) -> None:
    cursor_file = tmp_path / "shadowserver_cursor.json"
    provider = ShadowserverProvider(cursor_file=cursor_file, api_key=None, api_secret=None)
    assert provider.next_item() is None


def test_shadowserver_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "shadowserver_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SAMPLE_SHADOWSERVER_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = ShadowserverProvider(
        cursor_file=cursor_file,
        api_key="key",
        api_secret="secret",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "shadowserver"
    assert "CobaltStrike" in item.title
    assert "203.0.113.45:8080" in item.title
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1071.001" in item.content
    assert "The Shadowserver Foundation" in item.content
    assert item.metadata["evidence_profile"] == "infrastructure_telemetry"
    assert "203.0.113.45" in item.metadata["indicators"]["ipv4"]

    # Acknowledge
    provider.acknowledge(item)

    # Subsequent poll returns None
    assert provider.next_item() is None


def test_shadowserver_error_handled(tmp_path: Path) -> None:
    cursor_file = tmp_path / "shadowserver_cursor.json"

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "server error"})

    client = httpx.Client(transport=httpx.MockTransport(error_handler))
    provider = ShadowserverProvider(
        cursor_file=cursor_file,
        api_key="key",
        api_secret="secret",
        client=client,
    )

    assert provider.next_item() is None
