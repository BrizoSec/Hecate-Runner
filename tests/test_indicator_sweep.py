"""Deterministic indicator-sweep drafts for narrative-free feed dumps."""

from __future__ import annotations

from hecate_runner.indicator_sweep import build_indicator_sweep, parse_indicator_inventory

# Verbatim shape of MISP's `_event_to_blurb` output for a ThreatFox event --
# the exact source that produced H-0023's fabricated "stolen credentials ...
# lateral movement" hypothesis and its unsupported T1091.
THREATFOX_BLURB = """MISP Event: ThreatFox IOCs for 2026-08-09
Org: abuse.ch
Threat Level: Medium
TLP: white
Tags: type:OSINT
Attributes (245 total): domain (146), ip-dst|port (78), url (21)
Link: https://localhost:8443/events/view/4927"""

OTX_BLURB = """OTX Pulse: Some campaign
Adversary/Attribution: Unknown
Indicators (51 total): FileHash-SHA256 (25), IPv4 (1), URL (8), hostname (9)
References: https://example.com/report"""


class TestParseIndicatorInventory:
    def test_parses_misp_attributes_line(self) -> None:
        assert parse_indicator_inventory(THREATFOX_BLURB) == {
            "domain": 146,
            "ip-dst|port": 78,
            "url": 21,
        }

    def test_parses_otx_indicators_line(self) -> None:
        assert parse_indicator_inventory(OTX_BLURB) == {
            "filehash-sha256": 25,
            "ipv4": 1,
            "url": 8,
            "hostname": 9,
        }

    def test_returns_empty_without_an_inventory_line(self) -> None:
        """No inventory line means we could not confirm this is a feed dump.

        The caller must treat that as "don't build a sweep draft" -- an
        empty result is an unrecognised source, not an empty source."""
        assert parse_indicator_inventory("RSS: A real report\nSummary: Actors did things.") == {}

    def test_sums_duplicate_type_spellings(self) -> None:
        blurb = "Attributes (30 total): domain (10), domain (20)"
        assert parse_indicator_inventory(blurb) == {"domain": 30}


class TestBuildIndicatorSweep:
    def test_hypothesis_states_indicator_presence_not_behavior(self) -> None:
        result = build_indicator_sweep(THREATFOX_BLURB, title="ThreatFox IOCs for 2026-08-09")

        assert result.hypothesis == (
            "Indicators published in ThreatFox IOCs for 2026-08-09 appear in environment telemetry."
        )
        assert "Adversaries use" not in result.hypothesis

    def test_invents_no_delivery_vector_actor_or_follow_on_activity(self) -> None:
        """Regression test for the exact fabrications seen in live drafts
        built from feeds containing only domains, IPs and URLs."""
        result = build_indicator_sweep(THREATFOX_BLURB)
        rendered = " ".join(
            [
                result.hypothesis,
                result.justification,
                result.behavior,
                result.evidence,
                *result.observables,
                *result.false_positives,
            ]
        ).lower()

        for fabrication in (
            "phishing",
            "credential",
            "lateral movement",
            "malware family",
            "account login",
        ):
            assert fabrication not in rendered

    def test_technique_list_is_empty(self) -> None:
        """An indicator list evidences no ATT&CK technique. Empty is the
        correct answer -- and now renders as an explicit reviewer-facing gap
        rather than a "TXXXX" placeholder that failed `hecate-agent hunt validate`."""
        assert build_indicator_sweep(THREATFOX_BLURB).techniques == []

    def test_telemetry_is_derived_from_indicator_types_present(self) -> None:
        result = build_indicator_sweep(THREATFOX_BLURB)

        assert "DNS query logs" in result.data_sources
        assert "Web proxy / HTTP logs" in result.data_sources
        assert "Network flow / firewall logs" in result.data_sources
        # No hashes in this feed, so no endpoint file telemetry claimed.
        assert not any("Endpoint" in source for source in result.data_sources)

    def test_hash_indicators_add_endpoint_telemetry(self) -> None:
        result = build_indicator_sweep(OTX_BLURB)

        assert any("Endpoint" in source for source in result.data_sources)

    def test_observables_carry_per_type_counts(self) -> None:
        result = build_indicator_sweep(THREATFOX_BLURB)

        assert any("146 in feed" in observable for observable in result.observables)

    def test_unmapped_indicator_type_is_reported_not_invented(self) -> None:
        """An unrecognised type must still be surfaced for the reviewer, but
        must not contribute a made-up telemetry source."""
        result = build_indicator_sweep("Attributes (3 total): weird-new-type (3)")

        assert result.data_sources == []
        assert any("weird-new-type" in observable for observable in result.observables)

    def test_falls_back_to_first_line_when_no_title_given(self) -> None:
        result = build_indicator_sweep(THREATFOX_BLURB)

        assert "ThreatFox IOCs for 2026-08-09" in result.hypothesis

    def test_source_label_handles_a_first_line_without_a_colon(self) -> None:
        result = build_indicator_sweep("Some bare feed name\nAttributes (3 total): domain (3)")

        assert "Some bare feed name" in result.hypothesis

    def test_source_label_falls_back_when_content_has_no_usable_first_line(self) -> None:
        result = build_indicator_sweep("")

        assert "the source feed" in result.hypothesis

    def test_stays_a_threat_report(self) -> None:
        """A feed dump is genuine threat intel -- it must not be tagged
        low-confidence, which exists to flag vendor marketing."""
        assert build_indicator_sweep(THREATFOX_BLURB).is_threat_report is True

    def test_result_is_not_empty(self) -> None:
        """`is_empty` gates the orchestrator's refund-and-bail path; a sweep
        draft must read as a real result."""
        assert not build_indicator_sweep(THREATFOX_BLURB).is_empty


def test_sweep_draft_is_tagged_indicator_sweep_not_low_confidence() -> None:
    """A feed dump is genuine threat intel; it must get its own triage tag
    rather than being lumped in with vendor marketing."""
    from hecate_runner.hunt_writer import _draft_tags

    result = build_indicator_sweep(THREATFOX_BLURB)
    tags = _draft_tags(result.is_threat_report, result.is_indicator_only)

    assert "indicator-sweep" in tags
    assert "low-confidence-source" not in tags
