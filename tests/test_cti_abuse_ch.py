"""Tests for Abuse.ch ThreatFox CTI provider."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from hecate_runner.config import Settings
from hecate_runner.cti import get_provider
from hecate_runner.cti.abuse_ch import (
    THREATFOX_API_URL,
    AbuseChCursorState,
    AbuseChProvider,
)

SAMPLE_THREATFOX_V1_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "id": "1001",
            "ioc": "198.51.100.99:443",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
            "malware": "win.redline_stealer",
            "malware_printable": "RedLine Stealer",
        },
        {
            "id": "1002",
            "ioc": "evil-malware-payload.org",
            "ioc_type": "domain",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Indicator that delivers a payload",
            "malware": "win.asyncrat",
            "malware_printable": "AsyncRAT",
        },
    ],
}

SAMPLE_LEGACY_JSON_EXPORT = {
    "1003": [
        {
            "id": 1003,
            "ioc_value": "https://malicious-lure.top/login.exe",
            "ioc_type": "url",
            "threat_type": "payload_delivery",
            "malware_printable": "Lumma Stealer",
        }
    ]
}


def test_abuse_ch_cursor_lifecycle(tmp_path: Path) -> None:
    cursor_file = tmp_path / "abuse_ch_cursor.json"
    cursor = AbuseChCursorState.from_file(cursor_file)
    assert cursor.last_id == 0

    cursor.last_id = 1001
    cursor.save(cursor_file)
    assert cursor_file.exists()

    reloaded = AbuseChCursorState.from_file(cursor_file)
    assert reloaded.last_id == 1001


def test_threatfox_api_v1_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "abuse_ch_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == THREATFOX_API_URL
        assert request.headers.get("Auth-Key") == "test-api-key"
        payload = json.loads(request.content.decode("utf-8"))
        assert payload.get("query") == "get_iocs"
        return httpx.Response(200, json=SAMPLE_THREATFOX_V1_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AbuseChProvider(
        cursor_file=cursor_file,
        api_key="test-api-key",
        client=client,
    )

    # First item
    item1 = provider.next_item()
    assert item1 is not None
    assert item1.source == "abuse_ch"
    assert item1.identifier == "1001"
    assert "RedLine Stealer" in item1.title
    assert "Indicators (1 total): ipv4 (1)" in item1.content
    assert item1.metadata["indicators"]["ipv4"] == ["198.51.100.99"]
    assert item1.metadata["indicator_only"] is True

    # Acknowledge first item
    provider.acknowledge(item1)
    reloaded_cursor = AbuseChCursorState.from_file(cursor_file)
    assert reloaded_cursor.last_id == 1001

    # Second item
    item2 = provider.next_item()
    assert item2 is not None
    assert item2.identifier == "1002"
    assert "AsyncRAT" in item2.title
    assert item2.metadata["indicators"]["domain"] == ["evil-malware-payload.org"]

    provider.acknowledge(item2)
    assert provider.next_item() is None
    provider.close()


def test_threatfox_legacy_fallback_when_api_fails(tmp_path: Path) -> None:
    cursor_file = tmp_path / "abuse_ch_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            # ThreatFox API fails or returns non-200
            return httpx.Response(500, json={"error": "server error"})
        # Legacy export returns data
        return httpx.Response(200, json=SAMPLE_LEGACY_JSON_EXPORT)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AbuseChProvider(
        cursor_file=cursor_file,
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.identifier == "1003"
    assert "Lumma Stealer" in item.title
    assert item.metadata["indicators"]["url"] == ["https://malicious-lure.top/login.exe"]
    provider.close()


def test_get_provider_abuse_ch_factory(tmp_path: Path) -> None:
    settings = Settings(
        hecate_workspace=tmp_path,
        cti_provider="abuse_ch",
        abusech_api_key="custom-test-key",
    )
    provider = get_provider("abuse_ch", settings=settings)
    assert isinstance(provider, AbuseChProvider)
    assert provider.name == "abuse_ch"
    assert provider.api_key == "custom-test-key"
    provider.close()
