"""Tests for FIRST.org EPSS CTI Provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.first_org import FirstOrgCursorState, FirstOrgProvider

SAMPLE_FIRST_ORG_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 395308,
    "offset": 0,
    "limit": 5,
    "data": [
        {
            "cve": "CVE-2024-3400",
            "epss": "0.975000000",
            "percentile": "0.999500000",
            "date": "2026-10-25",
        },
        {
            "cve": "CVE-2024-21893",
            "epss": "0.920000000",
            "percentile": "0.985000000",
            "date": "2026-10-25",
        },
    ],
}


def test_first_org_cursor_lifecycle(tmp_path: Path) -> None:
    cursor_file = tmp_path / "first_org_cursor.json"
    cursor = FirstOrgCursorState.load(cursor_file)
    assert not cursor.already_seen("CVE-2024-3400")

    cursor.advance("CVE-2024-3400", "2026-10-25")
    cursor.save(cursor_file)

    loaded = FirstOrgCursorState.load(cursor_file)
    assert loaded.already_seen("CVE-2024-3400")
    assert loaded.last_processed_date == "2026-10-25"


def test_first_org_provider_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "first_org_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("order") == "!epss"
        return httpx.Response(200, json=SAMPLE_FIRST_ORG_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = FirstOrgProvider(
        cursor_file=cursor_file,
        min_epss=0.50,
        min_percentile=0.85,
        client=client,
    )

    # First item: CVE-2024-3400
    item = provider.next_item()
    assert item is not None
    assert item.source == "first_org"
    assert "CVE-2024-3400" in item.title
    assert "0.9750" in item.content or "97.5%" in item.content
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1190" in item.content
    assert item.metadata["evidence_profile"] == "vulnerability_advisory"
    assert item.metadata["cve"] == "CVE-2024-3400"

    # Acknowledge
    provider.acknowledge(item)

    # Second item: CVE-2024-21893
    second = provider.next_item()
    assert second is not None
    assert "CVE-2024-21893" in second.title

    provider.acknowledge(second)

    # Subsequent poll returns None
    assert provider.next_item() is None


def test_first_org_threshold_filtering(tmp_path: Path) -> None:
    cursor_file = tmp_path / "first_org_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "cve": "CVE-2020-0001",
                        "epss": "0.100000000",
                        "percentile": "0.500000000",
                        "date": "2026-10-25",
                    }
                ]
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = FirstOrgProvider(
        cursor_file=cursor_file,
        min_epss=0.50,
        min_percentile=0.85,
        client=client,
    )

    # Filtered out due to epss < 0.50
    assert provider.next_item() is None


def test_first_org_kev_enrichment(tmp_path: Path) -> None:
    cursor_file = tmp_path / "first_org_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if "known_exploited_vulnerabilities.json" in url_str:
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-3400",
                            "vendorProject": "Palo Alto Networks",
                            "product": "PAN-OS",
                            "vulnerabilityName": "Command Injection Vulnerability",
                            "shortDescription": "PAN-OS contains a command injection vulnerability in GlobalProtect feature.",
                            "knownRansomwareCampaignUse": "Known",
                        }
                    ]
                },
            )
        if "api.first.org" in url_str:
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "cve": "CVE-2024-3400",
                            "epss": "0.98",
                            "percentile": "0.99",
                            "date": "2026-10-25",
                        }
                    ]
                },
            )
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = FirstOrgProvider(
        cursor_file=cursor_file,
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.metadata["vendor"] == "Palo Alto Networks"
    assert item.metadata["product"] == "PAN-OS"
    assert item.metadata["ransomware_use"] == "Known"
    assert "Palo Alto Networks" in item.content
    assert "PAN-OS contains a command injection" in item.content
    assert "Known Ransomware Campaign Use: Known" in item.content
