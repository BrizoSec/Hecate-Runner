"""Unit tests for ANY.RUN Interactive Sandbox Detonation CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.anyrun import AnyRunCursorState, AnyRunProvider, _infer_techniques

SAMPLE_ANYRUN_API_RESPONSE = {
    "data": [
        {
            "task_id": "9b12a884-7a13-40f5-bc82-3d84fbbca311",
            "name": "malicious_invoice.exe",
            "verdict": "malicious",
            "tags": ["lumma", "stealer", "trojan"],
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            "os": "Windows 11 64-bit",
            "network_count": 12,
            "commands": [
                "powershell.exe -enc aQB3AHIA...",
                "cmd.exe /c whoami /all",
                "schtasks /create /tn 'Updater' /tr 'evil.exe'",
            ],
        },
        {
            "task_id": "benign-12345",
            "name": "calc.exe",
            "verdict": "clean",
            "tags": ["calculator"],
            "hashes": ["abc12345"],
            "commands": [],
        },
    ]
}

SAMPLE_ANYRUN_RSS_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>ANY.RUN Cybersecurity Blog</title>
    <link>https://any.run/cybersecurity-blog/</link>
    <item>
      <title>Unmasking Lumma Stealer Execution via PowerShell Delivery</title>
      <link>https://any.run/cybersecurity-blog/lumma-stealer-powershell/</link>
      <guid>https://any.run/cybersecurity-blog/?p=98765</guid>
      <pubDate>Mon, 25 Oct 2026 12:00:00 +0000</pubDate>
      <description>Detailed interactive sandbox analysis of Lumma stealer executing powershell commands and connecting to 198.51.100.22.</description>
      <content:encoded><![CDATA[<p>The sample dropped Lumma stealer hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and initiated C2 beaconing using powershell.exe to 198.51.100.22.</p>]]></content:encoded>
    </item>
  </channel>
</rss>
"""


def test_anyrun_cursor_lifecycle(tmp_path: Path) -> None:
    cursor_file = tmp_path / "anyrun_cursor.json"
    cursor = AnyRunCursorState.load(cursor_file)
    assert not cursor.already_seen("task-123")

    cursor.advance("task-123")
    assert cursor.already_seen("task-123")
    cursor.save(cursor_file)

    loaded = AnyRunCursorState.load(cursor_file)
    assert loaded.already_seen("task-123")


def test_anyrun_api_mode_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "anyrun_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "api.any.run" in str(request.url)
        assert request.headers.get("Authorization") == "API-Key secret-anyrun-key"
        return httpx.Response(200, json=SAMPLE_ANYRUN_API_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = AnyRunProvider(
        cursor_file=cursor_file,
        api_key="secret-anyrun-key",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "anyrun"
    assert "malicious_invoice.exe" in item.title
    assert item.metadata.get("evidence_profile") == "sandbox_execution"
    assert item.metadata.get("task_id") == "9b12a884-7a13-40f5-bc82-3d84fbbca311"
    assert "powershell.exe -enc" in item.content
    assert "T1059.001" in item.content

    # Acknowledge and ensure next poll yields None (benign item skipped)
    provider.acknowledge(item)
    assert provider.next_item() is None


def test_anyrun_rss_feed_fallback(tmp_path: Path) -> None:
    cursor_file = tmp_path / "anyrun_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert "any.run/cybersecurity-blog/feed/" in str(request.url)
        return httpx.Response(200, text=SAMPLE_ANYRUN_RSS_FEED)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    # No API key configured -> falls back to RSS feed
    provider = AnyRunProvider(
        cursor_file=cursor_file,
        api_key=None,
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "anyrun"
    assert "Lumma Stealer" in item.title
    assert item.metadata.get("evidence_profile") == "sandbox_execution"
    assert "198.51.100.22" in item.content
    assert "T1059.001" in item.content

    provider.acknowledge(item)
    assert provider.next_item() is None


def test_infer_techniques() -> None:
    techniques = _infer_techniques(
        "Execution using powershell.exe and registry run keys for persistence"
    )
    assert "T1059.001" in techniques
    assert "T1547.001" in techniques
