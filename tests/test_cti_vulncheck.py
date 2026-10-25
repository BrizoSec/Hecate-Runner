"""Tests for VulnCheck KEV CTI provider."""

from __future__ import annotations

from pathlib import Path

import httpx

from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE
from hecate_runner.cti.vulncheck import (
    VulnCheckCursorState,
    VulnCheckProvider,
    _infer_attack_techniques,
)

SAMPLE_VULNCHECK_RESPONSE = {
    "data": [
        {
            "cve": ["CVE-2024-3400"],
            "name": "Palo Alto Networks PAN-OS Command Injection",
            "vendor": "Palo Alto Networks",
            "product": "PAN-OS GlobalProtect",
            "date_added": "2024-04-12T00:00:00Z",
            "exploit_type": "weaponized",
            "vulncheck_reported_exploitation": True,
            "threat_actors": ["UTA0218"],
            "vulncheck_tags": ["Initial Access", "Ransomware"],
            "short_description": "A command injection vulnerability in the GlobalProtect feature of PAN-OS allows an unauthenticated attacker to execute arbitrary code with root privileges.",
            "references": [
                "https://vulncheck.com/advisories/vc-2024-pan-os",
                "https://security.paloaltonetworks.com/CVE-2024-3400",
            ],
        }
    ]
}


def test_vulncheck_cursor_lifecycle(tmp_path: Path) -> None:
    cursor_file = tmp_path / "vc_cursor.json"
    cursor = VulnCheckCursorState.load(cursor_file)
    assert not cursor.already_seen("CVE-2024-3400")

    cursor.advance("CVE-2024-3400", "2024-04-12T00:00:00Z")
    cursor.save(cursor_file)

    loaded = VulnCheckCursorState.load(cursor_file)
    assert loaded.already_seen("CVE-2024-3400")
    assert loaded.last_date_added == "2024-04-12T00:00:00Z"


def test_infer_attack_techniques() -> None:
    # Public-facing RCE
    v1 = {"short_description": "Unauthenticated remote code execution in web admin panel"}
    assert "T1190" in _infer_attack_techniques(v1)

    # Local privilege escalation
    v2 = {"short_description": "Local privilege escalation allows normal user to obtain root"}
    assert "T1068" in _infer_attack_techniques(v2)

    # Client software execution
    v3 = {"short_description": "Buffer overflow in PDF reader client application"}
    assert "T1203" in _infer_attack_techniques(v3)


def test_vulncheck_provider_unconfigured_skips(tmp_path: Path) -> None:
    cursor_file = tmp_path / "vc_cursor.json"
    provider = VulnCheckProvider(cursor_file=cursor_file, api_key=None)
    assert provider.next_item() is None


def test_vulncheck_provider_poll_and_acknowledge(tmp_path: Path) -> None:
    cursor_file = tmp_path / "vc_cursor.json"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer secret-vulncheck-token"
        return httpx.Response(200, json=SAMPLE_VULNCHECK_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = VulnCheckProvider(
        cursor_file=cursor_file,
        api_key="secret-vulncheck-token",
        client=client,
    )

    item = provider.next_item()
    assert item is not None
    assert item.source == "vulncheck"
    assert "CVE-2024-3400" in item.title
    assert "Palo Alto Networks" in item.content
    assert item.source_url == "https://vulncheck.com/cve/CVE-2024-3400"
    assert ATTACK_TECHNIQUE_LINE in item.content
    assert "T1190" in item.content
    assert "UTA0218" in item.content
    assert "WEAPONIZED" in item.content
    assert item.metadata["evidence_profile"] == "vulnerability_exploitation"
    assert item.metadata["cve"] == "CVE-2024-3400"

    # Acknowledge
    provider.acknowledge(item)

    # Subsequent poll returns None
    assert provider.next_item() is None


def test_vulncheck_provider_rate_limit_handled(tmp_path: Path) -> None:
    cursor_file = tmp_path / "vc_cursor.json"

    def error_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"message": "rate limit exceeded"})

    client = httpx.Client(transport=httpx.MockTransport(error_handler))
    provider = VulnCheckProvider(
        cursor_file=cursor_file,
        api_key="token",
        client=client,
    )

    assert provider.next_item() is None
