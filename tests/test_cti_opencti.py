"""Unit tests for OpenCTI STIX 2.1 GraphQL CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.opencti import OpenCTICursorState, OpenCTIProvider

SAMPLE_OPENCTI_GRAPHQL_RESPONSE = {
    "data": {
        "reports": {
            "edges": [
                {
                    "node": {
                        "id": "report--b3f2f09a-6a5b-4ec7-9cb5-ef5901234567",
                        "standard_id": "report--b3f2f09a-6a5b-4ec7-9cb5-ef5901234567",
                        "name": "Volt Typhoon Living Off the Land Campaign",
                        "description": "Volt Typhoon observed utilizing wmic, powershell, and ntdsutil for credential dumping.",
                        "published": "2026-10-25T14:30:00Z",
                        "confidence": 90,
                        "objects": {
                            "edges": [
                                {
                                    "node": {
                                        "id": "threat-actor--volt-typhoon",
                                        "name": "Volt Typhoon",
                                    }
                                },
                                {
                                    "node": {
                                        "id": "malware--custom-webshell",
                                        "name": "Custom Webshell",
                                    }
                                },
                                {
                                    "node": {
                                        "id": "attack-pattern--credential-dumping",
                                        "name": "OS Credential Dumping: NTDS",
                                        "x_mitre_id": "T1003.003",
                                    }
                                },
                                {
                                    "node": {
                                        "id": "indicator--wmic-process",
                                        "name": "wmic.exe process call create",
                                        "pattern": "[process:command_line MATCHES 'wmic.*process.*create']",
                                    }
                                },
                            ]
                        },
                    }
                }
            ]
        }
    }
}

SAMPLE_OPENCTI_STIX_FALLBACK = {
    "type": "bundle",
    "id": "bundle--opencti-fallback",
    "objects": [
        {
            "type": "report",
            "id": "report--cisa-kev-stix-1234",
            "name": "CISA KEV Exploit Activity Report",
            "description": "Active exploitation of T1190 vulnerability with PowerShell persistence via T1059.001.",
            "published": "2026-10-25T10:00:00Z",
        }
    ],
}


def test_opencti_cursor_lifecycle(tmp_path: Path) -> None:
    cursor_file = tmp_path / "opencti_cursor.json"
    cursor = OpenCTICursorState.load(cursor_file)
    assert not cursor.already_seen("report-123")

    cursor.advance("report-123")
    assert cursor.already_seen("report-123")
    cursor.save(cursor_file)

    loaded = OpenCTICursorState.load(cursor_file)
    assert loaded.already_seen("report-123")


def test_opencti_graphql_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "opencti_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://opencti.internal/graphql"
        assert request.headers.get("Authorization") == "Bearer my-opencti-token"
        assert request.method == "POST"
        return httpx.Response(200, json=SAMPLE_OPENCTI_GRAPHQL_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = OpenCTIProvider(
        cursor_file=cursor_file,
        base_url="https://opencti.internal",
        api_token="my-opencti-token",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "opencti"
    assert "Volt Typhoon" in item.title
    assert item.metadata.get("evidence_profile") == "procedural_intrusion"
    assert "Volt Typhoon" in item.metadata.get("actors", [])
    assert "Custom Webshell" in item.metadata.get("malware", [])
    assert "T1003.003" in item.content
    assert "wmic.exe process call create" in item.content

    provider.acknowledge(item)
    assert provider.next_item() is None


def test_opencti_stix_fallback(tmp_path: Path) -> None:
    cursor_file = tmp_path / "opencti_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "DATA-TEST-STIX2_v2.json" in str(request.url)
        return httpx.Response(200, json=SAMPLE_OPENCTI_STIX_FALLBACK)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    # Unconfigured credentials -> falls back to open community STIX bundle
    provider = OpenCTIProvider(
        cursor_file=cursor_file,
        base_url="",
        api_token="",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "opencti"
    assert "CISA KEV Exploit Activity Report" in item.title
    assert item.metadata.get("evidence_profile") == "procedural_intrusion"
    assert "T1190" in item.content
    assert "T1059.001" in item.content

    provider.acknowledge(item)
    assert provider.next_item() is None
