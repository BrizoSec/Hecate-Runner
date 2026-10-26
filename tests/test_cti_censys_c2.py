"""Tests for Censys C2 infrastructure CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.censys_c2 import (
    CensysC2Provider,
    CensysCursorState,
)

SAMPLE_CENSYS_SEARCH_RESPONSE = {
    "result": {
        "hits": [
            {
                "ip": "198.51.100.77",
                "location": {"country": "Netherlands"},
                "autonomous_system": {"asn": 12345, "name": "Bulletproof Hosting BV"},
                "services": [
                    {
                        "port": 50050,
                        "service_name": "COBALT_STRIKE",
                        "tls": {
                            "jarm": "07d14d16d21d21d07c42d41407d41d4ae3d3e5896041892ff5da154584d1c4",
                            "ja4": "t13d1516h2_8daaf6152771_019a76b17a1d",
                            "certificate": {
                                "parsed": {
                                    "subject_dn": "C=US, ST=DC, L=Washington, O=CobaltStrike, CN=Major"
                                }
                            },
                        },
                    }
                ],
            }
        ]
    }
}


def test_censys_cursor_state(tmp_path: Path) -> None:
    cursor_file = tmp_path / "censys_c2_cursor.json"
    cursor = CensysCursorState.load(cursor_file)
    assert not cursor.already_seen("198.51.100.77:50050")

    cursor.advance("198.51.100.77:50050")
    cursor.save(cursor_file)

    loaded = CensysCursorState.load(cursor_file)
    assert loaded.already_seen("198.51.100.77:50050")
    assert not loaded.already_seen("198.51.100.88:443")


def test_censys_c2_unconfigured_skips(tmp_path: Path) -> None:
    cursor_file = tmp_path / "censys_c2_cursor.json"
    provider = CensysC2Provider(cursor_file=cursor_file, api_token=None)
    assert provider.next_item() is None


def test_censys_c2_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "censys_c2_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer secret-censys-token"
        return httpx.Response(200, json=SAMPLE_CENSYS_SEARCH_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = CensysC2Provider(
        cursor_file=cursor_file,
        api_token="secret-censys-token",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "censys_c2"
    assert "COBALT_STRIKE" in item.title
    assert "198.51.100.77:50050" in item.title
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1071.001" in item.content
    assert "JARM: 07d14d16d21d" in item.content
    assert "JA4: t13d1516h2" in item.content
    assert item.metadata["evidence_profile"] == "infrastructure_telemetry"
    assert "198.51.100.77" in item.metadata["indicators"]["ipv4"]
    assert "jarm" in item.metadata["indicators"]

    # Acknowledge
    provider.acknowledge(item)

    # Subsequent poll returns None
    assert provider.next_item() is None


def test_censys_c2_quota_limit_handled(tmp_path: Path) -> None:
    cursor_file = tmp_path / "censys_c2_cursor.json"

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"errors": [{"message": "insufficient balance"}]})

    client = httpx.Client(transport=httpx.MockTransport(error_handler))
    provider = CensysC2Provider(
        cursor_file=cursor_file,
        api_token="secret-censys-token",
        client=client,
    )

    assert provider.next_item() is None


def test_censys_c2_free_tier_organization_id_skip(tmp_path: Path) -> None:
    cursor_file = tmp_path / "censys_c2_cursor.json"

    def free_tier_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "title": "Forbidden",
                "status": 403,
                "detail": "This endpoint requires an organization ID for API access. Free users can only access this endpoint through the Platform UI.",
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(free_tier_handler))
    provider = CensysC2Provider(
        cursor_file=cursor_file,
        api_token="personal-access-token",
        client=client,
    )

    # Should gracefully skip and return None without raising CensysError
    assert provider.next_item() is None


def test_censys_c2_v3_platform_nested_host(tmp_path: Path) -> None:
    cursor_file = tmp_path / "censys_c2_cursor.json"
    v3_response = {
        "result": {
            "hits": [
                {
                    "host": {
                        "ip": "203.0.113.55",
                        "location": {"country": "Germany"},
                        "autonomous_system": {"asn": 54321, "name": "C2 Hosting AS"},
                        "services": [
                            {
                                "port": 8443,
                                "service_name": "SLIVER",
                                "tls": {
                                    "jarm": "29d29d15d29d29d00042d42d29d29d",
                                },
                            }
                        ],
                    }
                }
            ]
        }
    }

    def v3_handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.headers.get("X-Organization-ID") == "my-org-uuid"
        return httpx.Response(200, json=v3_response)

    client = httpx.Client(transport=httpx.MockTransport(v3_handler))
    provider = CensysC2Provider(
        cursor_file=cursor_file,
        api_token="enterprise-token",
        organization_id="my-org-uuid",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert "203.0.113.55:8443" in item.title
    assert "SLIVER" in item.title
    assert item.metadata["indicators"]["ipv4"] == ["203.0.113.55"]
    provider.close()
