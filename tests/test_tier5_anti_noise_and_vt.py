"""Tests for Tier 5 Anti-Noise (GreyNoise / RIOT) and VirusTotal Behavioral Graph integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from hecate_runner.config import Settings
from hecate_runner.cti import CTIItem
from hecate_runner.cti_triage import anti_noise_verdict, triage


def test_settings_tier5_configuration(tmp_path: Path):
    s = Settings(
        hecate_workspace=tmp_path,
        vt_api_key="secret-vt-key",
        greynoise_api_key="secret-gn-key",
        anti_noise_triage=True,
        vt_behavior_enrichment=True,
    )
    assert s.vt_api_key == "secret-vt-key"
    assert s.greynoise_api_key == "secret-gn-key"
    assert s.anti_noise_triage is True
    assert s.vt_behavior_enrichment is True

    # Check masking
    dumped = s.redacted_dict()
    assert dumped["vt_api_key"] == "<redacted>"
    assert dumped["greynoise_api_key"] == "<redacted>"


def test_triage_parks_on_riot_benign_service():
    item = CTIItem(
        content="Suspicious network flow to 1.1.1.1",
        source="rss",
        title="Network Anomaly",
        metadata={"indicators": {"ipv4": ["1.1.1.1"]}},
    )
    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": False,
            "riot": True,
            "classification": "benign",
            "actor": "Cloudflare DNS",
            "tags": [],
            "raw_status": 200,
        }
        verdict = triage(item, anti_noise_enabled=True)
        assert verdict.park is True
        assert "verified benign enterprise infrastructure" in verdict.reason
        assert "Cloudflare DNS" in verdict.reason


def test_triage_parks_on_known_benign_scanner():
    item = CTIItem(
        content="Perimeter probe from 65.49.20.70",
        source="misp",
        title="Port Scan Alert",
        metadata={"indicators": {"ipv4": ["65.49.20.70"]}},
    )
    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": True,
            "riot": False,
            "classification": "benign",
            "actor": "ShadowServer.org",
            "tags": ["Ping Scanner"],
            "raw_status": 200,
        }
        verdict = triage(item, anti_noise_enabled=True)
        assert verdict.park is True
        assert "known benign scanner" in verdict.reason
        assert "ShadowServer.org" in verdict.reason


def test_triage_anti_noise_disabled_allows_item():
    item = CTIItem(
        content="Probe from 65.49.20.70",
        source="rss",
        title="Targeted Attack",
        metadata={"indicators": {"ipv4": ["65.49.20.70"]}},
    )
    # Even if GreyNoise would flag it, anti_noise_enabled=False skips the check
    verdict = triage(item, anti_noise_enabled=False)
    assert verdict.park is False


def test_anti_noise_tags_mass_scanner_without_parking():
    item = CTIItem(
        content="Scanning from 198.51.100.44",
        source="otx",
        metadata={"indicators": {"ipv4": ["198.51.100.44"]}},
    )
    with patch("hecate_agent.api.extract_greynoise_context") as mock_gn:
        mock_gn.return_value = {
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "actor": "Mirai",
            "tags": ["Telnet Scanner"],
            "raw_status": 200,
        }
        verdict = anti_noise_verdict(item)
        assert verdict is None
        assert item.metadata["noise_classification"] == "mass_scanner"
        assert item.metadata["scanner_actor"] == "Mirai"
        assert item.metadata["scanner_tags"] == ["Telnet Scanner"]
