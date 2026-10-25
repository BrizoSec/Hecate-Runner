"""Tests for Microsoft Security Response Center (MSRC) CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.msrc import MsrcCursorState, MsrcProvider


def test_msrc_cursor_load_save(tmp_path: Path) -> None:
    cursor_file = tmp_path / "msrc_cursor.json"
    state = MsrcCursorState.load(cursor_file)
    assert state.seen_cves == []

    state.advance("CVE-2024-38063")
    state.save(cursor_file)

    reloaded = MsrcCursorState.load(cursor_file)
    assert reloaded.seen_cves == ["CVE-2024-38063"]


def test_msrc_provider_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "msrc_cursor.json"

    updates_data = {
        "value": [
            {
                "ID": "2024-Aug",
                "CurrentReleaseDate": "2026-10-15T00:00:00Z",
            }
        ]
    }

    doc_data = {
        "Vulnerability": [
            {
                "CVE": "CVE-2024-38063",
                "Title": {"Value": "Windows TCP/IP Remote Code Execution Vulnerability"},
                "CVSSScoreSets": [
                    {"BaseScore": 9.8, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
                "Threats": [
                    {"Type": 3, "Description": {"Value": "Critical"}},
                    {"Type": 0, "Description": {"Value": "Remote Code Execution"}},
                    {"Type": 1, "Description": {"Value": "Exploitation More Likely"}},
                ],
                "Notes": [
                    {
                        "Value": "<p>An unauthenticated attacker could send specially crafted IPv6 packets.</p>"
                    }
                ],
                "ReleaseDate": "2024-08-13T07:00:00Z",
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if "updates" in url_str:
            return httpx.Response(200, json=updates_data)
        if "2024-Aug" in url_str:
            return httpx.Response(200, json=doc_data)
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = MsrcProvider(cursor_file=cursor_file, client=mock_client)

    item = provider.poll()
    assert item is not None
    assert item.identifier == "msrc-cve-2024-38063"
    assert "CVE-2024-38063" in item.title
    assert "Windows TCP/IP" in item.title
    assert "CVSS v3 Score: 9.8" in item.content
    assert "Severity: Critical" in item.content
    assert "An unauthenticated attacker could send" in item.content
    assert item.metadata.get("evidence_profile") == "vulnerability_advisory"
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1190" in item.content

    # Acknowledge
    provider.acknowledge(item)

    # Next poll should be empty
    second_poll = provider.poll()
    assert second_poll is None


def test_msrc_provider_filters_low_impact(tmp_path: Path) -> None:
    cursor_file = tmp_path / "msrc_cursor.json"

    updates_data = {"value": [{"ID": "2024-Aug"}]}
    doc_data = {
        "Vulnerability": [
            {
                "CVE": "CVE-2024-0001",
                "Title": {"Value": "Informational Documentation Update"},
                "CVSSScoreSets": [{"BaseScore": 2.1}],
                "Threats": [
                    {"Type": 3, "Description": {"Value": "Low"}},
                    {"Type": 1, "Description": {"Value": "Exploitation Unlikely"}},
                ],
            }
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if "updates" in str(request.url):
            return httpx.Response(200, json=updates_data)
        return httpx.Response(200, json=doc_data)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = MsrcProvider(cursor_file=cursor_file, client=mock_client)

    item = provider.poll()
    assert item is None
