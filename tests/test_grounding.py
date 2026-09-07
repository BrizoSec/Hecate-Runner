"""Tests for the post-draft grounding audit.

The audit's value depends entirely on its false-positive rate. A reviewer who
sees a behavioural rule reported as a fabricated indicator learns to ignore
the section, at which point a real fabrication passes unnoticed -- so most of
these tests are about what it must *not* flag.
"""

from __future__ import annotations

from hecate_runner.grounding import TechniqueFact, audit_draft, render_grounding_section

# The real source blurb shape, abridged from MISP event 476.
CTI = """MISP Event: The Chrysalis Backdoor: A Deep Dive into Lotus Blossom's toolkit
MITRE ATT&CK Techniques: T1005, T1059.003, T1071.001, T1574.002
Key indicators:
  filename: %ALLUSERSPROFILE%\\USOShared\\svchost.exe
  hostname: api.skycloudcenter.com, api.wiresguard.com
  ip-dst: 95.179.213.0, 59.110.7.32
Analyst note: Cobalt Strike HTTPS beacon with http-get api.wiresguard.com/update/v1
"""
CTI_TECHNIQUES = ["T1005", "T1059.003", "T1071.001", "T1574.002"]


def _rule(body: str) -> str:
    return f"```yaml\n{body}\n```"


# --- Fabrication detection -------------------------------------------------


def test_flags_a_cve_no_source_names():
    report = audit_draft(
        draft_text="CVE-2024-1234 is associated with the initial access vector.",
        cti_text=CTI,
    )
    assert [c.value for c in report.unsupported] == ["CVE-2024-1234"]


def test_accepts_a_cve_the_research_document_cites():
    report = audit_draft(
        draft_text="CVE-2021-44228 was exploited.",
        cti_text=CTI,
        research_text="Log4Shell (CVE-2021-44228) advisory",
    )
    assert report.is_clean


def test_flags_a_rule_matching_infrastructure_from_no_source():
    report = audit_draft(
        draft_text=_rule("selection:\n  DestinationHostname: evil-c2.example.io"),
        cti_text=CTI,
    )
    assert [c.value for c in report.unsupported] == ["evil-c2.example.io"]


def test_confirms_the_real_c2_infrastructure():
    report = audit_draft(
        draft_text=_rule(
            "selection:\n  DestinationHostname: api.wiresguard.com\n  DestinationIp: 95.179.213.0"
        ),
        cti_text=CTI,
    )
    assert report.is_clean
    assert {c.value for c in report.claims} == {"api.wiresguard.com", "95.179.213.0"}


# --- What it must NOT flag -------------------------------------------------


def test_a_behavioural_rule_is_not_a_fabrication():
    """Process names are what a behavioural rule is supposed to contain."""
    report = audit_draft(
        draft_text=_rule(
            "selection:\n"
            "  Image|endswith: \\powershell.exe\n"
            "  OriginalFileName: rundll32.exe\n"
            "  CommandLine|contains: -EncodedCommand"
        ),
        cti_text=CTI,
    )
    assert report.claims == []


def test_scaffolding_hosts_are_ignored():
    """The workspace's own MISP link would otherwise be flagged on every draft."""
    report = audit_draft(
        draft_text=_rule("references:\n  - https://localhost:8443/events/view/476"),
        cti_text=CTI,
    )
    assert report.is_clean


def test_prose_indicators_are_not_audited():
    """Only rule bodies are checked -- prose legitimately paraphrases, and the
    rules are what would actually be run."""
    report = audit_draft(
        draft_text="The actor also used cdn.other-report.net, per open reporting.",
        cti_text=CTI,
    )
    assert not any(c.kind == "indicator" for c in report.claims)


# --- Technique provenance --------------------------------------------------


def test_technique_named_by_the_source_is_asserted():
    report = audit_draft(
        draft_text="techniques: T1059.003", cti_text=CTI, cti_techniques=CTI_TECHNIQUES
    )
    assert report.claims[0].status == "asserted"


def test_subtechnique_of_an_asserted_parent_still_counts_as_asserted():
    report = audit_draft(draft_text="T1071", cti_text=CTI, cti_techniques=["T1071.001"])
    assert report.claims[0].status == "asserted"


def test_technique_the_hypothesis_invented_is_marked_inferred_not_unsupported():
    """Inferring a technique is legitimate hunting; it is not fabrication, and
    calling it that would make the audit cry wolf."""
    report = audit_draft(draft_text="T1566", cti_text=CTI, cti_techniques=CTI_TECHNIQUES)
    assert report.claims[0].status == "derived"
    assert report.is_clean


def test_claims_are_deduplicated():
    report = audit_draft(
        draft_text="T1005 T1005 T1005", cti_text=CTI, cti_techniques=CTI_TECHNIQUES
    )
    assert len(report.claims) == 1


# --- Rendering -------------------------------------------------------------


def test_rendered_section_leads_with_the_unsupported_claims():
    report = audit_draft(
        draft_text="CVE-2024-1234 " + _rule("selection:\n  DestinationIp: 203.0.113.99"),
        cti_text=CTI,
    )
    rendered = render_grounding_section(report)
    first_line = rendered.splitlines()[0]
    assert "2 claim(s) trace to no source" in first_line
    assert "**UNSUPPORTED**" in rendered


def test_rendered_section_says_so_when_everything_checks_out():
    report = audit_draft(draft_text="T1005", cti_text=CTI, cti_techniques=CTI_TECHNIQUES)
    assert "traces back to a source" in render_grounding_section(report)


def test_rendered_section_handles_a_draft_with_no_claims():
    report = audit_draft(draft_text="No hunt content here.", cti_text=CTI)
    assert "No checkable claims" in render_grounding_section(report)


def test_counts_add_up():
    report = audit_draft(
        draft_text="T1005 T1566 CVE-2024-1234",
        cti_text=CTI,
        cti_techniques=CTI_TECHNIQUES,
    )
    assert report.counts == {"asserted": 1, "corroborated": 0, "derived": 1, "unsupported": 1}


# --- Evidence ranking ------------------------------------------------------


def test_a_claim_only_the_research_supports_is_corroborated_not_asserted():
    """The circular case. R-0611 carries a CVE the source event never
    mentioned; treating the research document as proof would let that
    fabrication come back as evidence in every hunt built from it."""
    report = audit_draft(
        draft_text="Initial access via CVE-2024-1234.",
        cti_text=CTI,
        research_text="CVE-2024-1234 is associated with the initial access vector.",
    )
    assert [c.status for c in report.claims] == ["corroborated"]
    # Not a fabrication -- but not evidence either.
    assert report.is_clean


def test_the_cti_outranks_the_research_document():
    report = audit_draft(
        draft_text=_rule("selection:\n  DestinationHostname: api.wiresguard.com"),
        cti_text=CTI,
        research_text="api.wiresguard.com also appears here",
    )
    assert report.claims[0].status == "asserted"


def test_rendered_section_warns_about_research_only_claims():
    report = audit_draft(
        draft_text="CVE-2021-44228", cti_text=CTI, research_text="CVE-2021-44228 advisory"
    )
    rendered = render_grounding_section(report)
    assert "rest on the research document alone" in rendered
    assert "research only" in rendered


# --- Technique validity ----------------------------------------------------


def test_a_technique_the_matrix_does_not_know_is_unsupported():
    """The Sigma generator proposed T1047.002, which has never existed. An
    invented ID looks exactly like a real mapping in frontmatter."""
    report = audit_draft(
        draft_text="techniques: T1047.002",
        cti_text=CTI,
        technique_facts={"T1047.002": TechniqueFact(valid=False)},
    )
    assert report.claims[0].status == "unsupported"
    assert "no such technique" in report.claims[0].note


def test_a_revoked_technique_is_still_asserted_but_says_so():
    report = audit_draft(
        draft_text="techniques: T1574.002",
        cti_text=CTI,
        cti_techniques=["T1574.002"],
        technique_facts={"T1574.002": TechniqueFact(valid=True, superseded_by="T1574.001")},
    )
    claim = report.claims[0]
    assert claim.status == "asserted"
    assert "superseded by T1574.001" in claim.note


def test_techniques_without_facts_fall_back_to_provenance_only():
    """Facts are optional; an audit run without them must still work."""
    report = audit_draft(draft_text="T1566", cti_text=CTI, cti_techniques=CTI_TECHNIQUES)
    assert report.claims[0].status == "derived"
