"""Tests for Cloud Threat Intelligence CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.cloud_threat import CloudThreatCursorState, CloudThreatProvider


def test_cloud_threat_cursor_load_save(tmp_path: Path) -> None:
    cursor_file = tmp_path / "cloud_threat_cursor.json"
    state = CloudThreatCursorState.load(cursor_file)
    assert state.seen_links == []

    state.advance("https://permiso.io/blog/test-article")
    state.save(cursor_file)

    reloaded = CloudThreatCursorState.load(cursor_file)
    assert reloaded.seen_links == ["https://permiso.io/blog/test-article"]


def test_cloud_threat_provider_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "cloud_threat_cursor.json"

    sample_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Cloud Chronicles</title>
    <link>https://permiso.io/blog</link>
    <item>
      <title>LUCR-3 Scattered Spider: Abusing AWS STS AssumeRole and Entra ID Service Principals</title>
      <link>https://permiso.io/blog/lucr-3-scattered-spider-cloud-intrusion</link>
      <description>&lt;p&gt;Adversaries compromised identity provider session tokens to execute sts:AssumeRoleWithWebIdentity, escalating privileges across AWS accounts and issuing Directory.ReadWrite.All consent grants.&lt;/p&gt;</description>
      <pubDate>Mon, 20 Oct 2026 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=sample_rss)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = CloudThreatProvider(
        cursor_file=cursor_file,
        feed_urls=["https://permiso.io/blog/rss.xml"],
        client=mock_client,
    )

    item = provider.poll()
    assert item is not None
    assert "Cloud Threat Intel:" in item.title
    assert "LUCR-3 Scattered Spider" in item.title
    assert item.metadata.get("evidence_profile") == "cloud_telemetry"
    assert "Observed Cloud IAM Operations:" in item.content
    assert "AssumeRole" in item.content
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1078.004" in item.content
    assert "T1098.001" in item.content

    # Acknowledge
    provider.acknowledge(item)

    # Next poll should be empty
    second_poll = provider.poll()
    assert second_poll is None


def test_cloud_threat_provider_handles_k8s_and_cves(tmp_path: Path) -> None:
    cursor_file = tmp_path / "cloud_threat_cursor.json"

    sample_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>AWS Security Bulletins</title>
    <link>https://aws.amazon.com/security/security-bulletins/</link>
    <item>
      <title>CVE-2026-103505 - Mount Option Injection in Kubernetes CSI Driver</title>
      <link>https://aws.amazon.com/security/security-bulletins/2026-103505/</link>
      <description>Privileged container escape using hostPath volume injection and kubectl cluster-admin token theft.</description>
      <pubDate>Sun, 25 Oct 2026 08:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=sample_rss)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = CloudThreatProvider(
        cursor_file=cursor_file,
        feed_urls=["https://aws.amazon.com/security/security-bulletins/feed/"],
        client=mock_client,
    )

    item = provider.poll()
    assert item is not None
    assert "CVE-2026-103505" in item.title
    assert "Associated CVEs: CVE-2026-103505" in item.content
    assert "T1610" in item.content
    assert "T1611" in item.content
