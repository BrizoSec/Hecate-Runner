"""Tests for Hatching Triage (tria.ge) dynamic sandbox CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.triage import (
    TriageCursorState,
    TriageProvider,
)

SAMPLE_SEARCH_RESPONSE = {
    "data": [
        {
            "id": "241025-abc123sample",
            "filename": "invoice_attachment.exe",
            "score": 10,
            "target": "windows10",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        }
    ]
}

SAMPLE_OVERVIEW_RESPONSE = {
    "sample": {
        "id": "241025-abc123sample",
        "filename": "invoice_attachment.exe",
        "score": 10,
        "target": "windows10",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "md5": "1234567890abcdef1234567890abcdef",
    },
    "analysis": {
        "score": 10,
        "family": ["LummaStealer"],
        "tags": ["stealer", "trojan"],
    },
    "extracted": [
        {
            "config": {
                "family": "LummaStealer",
                "c2": ["https://lumma-c2-drop.xyz/api", "https://backup-c2.top/gate"],
                "botnet": "campaign_october_2026",
                "mutex": "Global\\LummaMutexSync",
            }
        }
    ],
    "signatures": [
        {
            "name": "PowerShell Command Invocation",
            "desc": "Spawns hidden powershell process to steal credentials",
            "ttp": "T1059.001",
            "marks": [{"command_line": "powershell.exe -w hidden -enc IAAuAC4A"}],
        },
        {
            "name": "Process Injection",
            "desc": "Injects shellcode into BitLockerToGo.exe",
            "ttp": ["T1055.001"],
            "marks": [],
        },
    ],
    "targets": [
        {
            "iocs": {
                "ips": ["198.51.100.88"],
                "domains": ["lumma-c2-drop.xyz"],
            }
        }
    ],
}


def test_triage_cursor_state(tmp_path: Path) -> None:
    cursor_file = tmp_path / "triage_cursor.json"
    cursor = TriageCursorState.load(cursor_file)
    assert not cursor.already_seen("sample-1")

    cursor.advance("sample-1")
    cursor.save(cursor_file)

    loaded = TriageCursorState.load(cursor_file)
    assert loaded.already_seen("sample-1")
    assert not loaded.already_seen("sample-2")


def test_triage_provider_unconfigured_skips(tmp_path: Path) -> None:
    cursor_file = tmp_path / "triage_cursor.json"
    provider = TriageProvider(cursor_file=cursor_file, api_key=None)
    assert provider.next_item() is None


def test_triage_provider_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "triage_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        assert request.headers.get("Authorization") == "Bearer secret-triage-token"
        if "/search" in url:
            return httpx.Response(200, json=SAMPLE_SEARCH_RESPONSE)
        if "/overview.json" in url:
            return httpx.Response(200, json=SAMPLE_OVERVIEW_RESPONSE)
        return httpx.Response(404, json={"message": "not found"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = TriageProvider(
        cursor_file=cursor_file,
        api_key="secret-triage-token",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "triage"
    assert "LummaStealer" in item.title
    assert item.source_url == "https://tria.ge/241025-abc123sample"
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1059.001" in item.content
    assert "T1055.001" in item.content
    assert "Extracted Process Executions & Command Lines:" in item.content
    assert "powershell.exe -w hidden -enc" in item.content
    assert "lumma-c2-drop.xyz" in item.content
    assert item.metadata["evidence_profile"] == "sandbox_detonation"
    assert "198.51.100.88" in item.metadata["indicators"]["ipv4"]
    assert "LummaMutexSync" in item.content

    # Acknowledge
    provider.acknowledge(item)

    # Subsequent poll returns None
    assert provider.next_item() is None


def test_triage_provider_auth_error_handled(tmp_path: Path) -> None:
    cursor_file = tmp_path / "triage_cursor.json"

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "unauthorized"})

    client = httpx.Client(transport=httpx.MockTransport(error_handler))
    provider = TriageProvider(
        cursor_file=cursor_file,
        api_key="bad-token",
        client=client,
    )

    item = provider.next_item()
    assert item is None
