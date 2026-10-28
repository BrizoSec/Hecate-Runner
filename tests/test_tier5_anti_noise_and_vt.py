"""Tests for Tier 5 Anti-Noise (GreyNoise / RIOT) and VirusTotal Behavioral Graph integration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from hecate_runner.config import Settings
from hecate_runner.cti import CTIItem
from hecate_runner.cti_triage import anti_noise_verdict, triage
from hecate_runner.orchestrator import Orchestrator


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


def test_vt_graph_preserves_source_assertions_and_keeps_sample_context_separate(
    settings, mock_hecate, monkeypatch
):
    """A sandbox label/contact is not evidence of that behavior in the reported intrusion."""
    sample = "a" * 64
    item = CTIItem(
        content="The report describes a remote-access program running on Windows.",
        source="manual",
        metadata={"techniques": ["T1219"], "indicators": {"sha256": [sample]}},
    )
    settings.vt_api_key = "test-key"
    settings.vt_behavior_enrichment = True
    settings.source_evidence_enabled = False
    settings.sigma_generation_enabled = False
    provider = MagicMock()
    provider.next_item.return_value = item
    monkeypatch.setattr("hecate_agent.api.extract_indicators", lambda _: {"hashes": [sample]})
    monkeypatch.setattr("hecate_agent.api.generate_enrichment_summary", lambda _: "")
    graph = {"mitre_techniques": [{"id": "T1485"}],
        "contacted_ips": ["203.0.113.9"], "contacted_domains": ["sandbox-only.test"]}
    monkeypatch.setattr("hecate_agent.api.extract_vt_behavior_graph", lambda _: graph)

    result = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    assert result.outcome == "draft_created"
    assert item.metadata["techniques"] == ["T1219"]
    assert "203.0.113.9" not in item.metadata["indicators"].get("ipv4", [])
    assert "sandbox-only.test" not in item.metadata["indicators"].get("domain", [])
    assert item.metadata["vt_behavior_graphs"] == [{"sample_hash": sample, "graph": graph}]
    context = mock_hecate.research_new.call_args.kwargs["source_context"]
    assert "SECONDARY OSINT ENRICHMENT" in context and "T1485" in context
