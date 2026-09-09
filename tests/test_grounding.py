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


# --- Named entities in prose (G2) ------------------------------------------


def test_flags_an_invented_malware_family():
    """The documented case: hypothesis generation invented "PureRAT and
    Overlord RAT" and both propagated into a hunt file as reported fact."""
    report = audit_draft(
        draft_text="Related tooling includes PureRAT and the Overlord RAT.",
        cti_text=CTI,
    )
    assert {c.value for c in report.unsupported} == {"PureRAT", "Overlord"}


def test_confirms_a_family_the_source_named():
    report = audit_draft(
        draft_text="The Chrysalis backdoor is delivered via a compromised installer.",
        cti_text="MISP Event: The Chrysalis Backdoor: a deep dive",
    )
    assert [c.status for c in report.claims] == ["asserted"]


def test_flags_an_actor_designator_no_source_names():
    report = audit_draft(draft_text="Attributed to APT41.", cti_text=CTI)
    assert [c.value for c in report.unsupported] == ["APT41"]


def test_a_generic_backdoor_claim_is_not_an_entity():
    """ "Adversaries deploy a backdoor" names nothing; flagging it would make
    the section noise, and noise is what gets a reviewer to skip it."""
    report = audit_draft(
        draft_text="Adversaries use obfuscated commands to deploy a backdoor on Windows systems.",
        cti_text=CTI,
    )
    assert not any(c.kind == "entity" for c in report.claims)


def test_all_caps_words_are_not_mistaken_for_camelcase_families():
    report = audit_draft(draft_text="This is a GREAT and THOROUGH analysis.", cti_text=CTI)
    assert report.claims == []


def test_entities_inside_rule_bodies_are_not_double_counted():
    """A Sigma selection naming a family derives from the prose above it; it
    is not an independent claim."""
    report = audit_draft(
        draft_text=_rule("selection:\n  Description: PureRAT loader"),
        cti_text=CTI,
    )
    assert not any(c.kind == "entity" for c in report.claims)


def test_entity_only_in_research_is_corroborated():
    report = audit_draft(
        draft_text="The Chrysalis backdoor was used.",
        cti_text="MISP Event: unrelated",
        research_text="Chrysalis is a Lotus Blossom tool",
    )
    assert [c.status for c in report.claims] == ["corroborated"]


# --- Indicator scoping: detection: only (G5) -------------------------------

_RULE_DRAFT = """### Justification

Prose about the campaign.

```yaml
title: Suspicious Beacon
description: Detects beaconing described at unit42.paloaltonetworks.com
references:
- https://unit42.paloaltonetworks.com/large-scale-credential-attacks/
author: hecate (auto-generated draft - requires analyst review)
logsource:
  category: network_connection
detection:
  selection:
    DestinationHostname: api.wiresguard.com
  condition: selection
falsepositives:
- Traffic to vendor.example-cdn.net during updates
level: medium
```
"""


def _indicators(draft, cti=""):
    report = audit_draft(draft_text=draft, cti_text=cti, research_text="", cti_techniques=[])
    return {c.value for c in report.claims if c.kind == "indicator"}


def test_the_citation_host_is_not_an_indicator():
    """`references:` cites the article the hunt came from. Auditing it graded
    the publisher's own domain as an indicator "asserted by CTI"."""
    assert "unit42.paloaltonetworks.com" not in _indicators(_RULE_DRAFT)


def test_the_detection_value_is_still_audited():
    """The narrowing must not cost the fabrication check anything."""
    assert "api.wiresguard.com" in _indicators(_RULE_DRAFT)


def test_a_fabricated_detection_domain_is_still_unsupported():
    report = audit_draft(
        draft_text=_RULE_DRAFT, cti_text="Nothing here", research_text="", cti_techniques=[]
    )
    verdict = {c.value: c.status for c in report.claims if c.kind == "indicator"}
    assert verdict["api.wiresguard.com"] == "unsupported"


def test_metadata_outside_detection_is_ignored():
    """description:, author: and falsepositives: are not run."""
    found = _indicators(_RULE_DRAFT)
    assert "vendor.example-cdn.net" not in found
    assert found == {"api.wiresguard.com"}


def test_a_block_without_a_detection_section_is_audited_whole():
    """Not a runnable rule. An audit should over-report here rather than go
    quiet -- the Sigma validator rejects these before they reach a hunt."""
    draft = "```yaml\ntitle: Broken\nreferences:\n- https://evil.example-c2.net/p\n```\n"
    assert "evil.example-c2.net" in _indicators(draft)


def test_detection_section_stops_at_the_next_top_level_key():
    from hecate_runner.grounding import _detection_section

    body = "detection:\n  selection:\n    a: 1\nfalsepositives:\n- b.example-fp.net\n"
    section = _detection_section(body)
    assert "a: 1" in section
    assert "b.example-fp.net" not in section


# --- Entity precision and recall (G9) --------------------------------------

from hecate_runner.grounding import _named_entities  # noqa: E402


def test_a_lowercase_token_is_not_a_malware_family():
    """re.IGNORECASE defeated the pattern's own [A-Z] anchor, so the OTX tag
    "chrome rat" was captured as a family named `chrome`."""
    assert _named_entities("session hijacking, post-exploitation, peep, chrome rat") == []


def test_a_generic_platform_noun_is_not_a_family():
    """ "Browser RAT" names a category, not a family. H-0003 graded `Browser`
    as an asserted malware name."""
    assert "Browser" not in _named_entities("PEEP: A Browser RAT Posing as a Chrome Extension")


def test_an_implementation_language_is_not_a_family():
    assert _named_entities("A JavaScript loader ran.") == []
    assert _named_entities("A PowerShell dropper ran.") == []


def test_a_based_suffix_is_a_description_not_a_name():
    assert _named_entities("A Rust-based loader dropped it.") == []


def test_an_all_caps_family_is_recovered():
    """Missed by both older patterns: the collocation yields the token before
    the category noun, and _CAMEL_MALWARE_RE needs a lowercase run."""
    assert "PEEP" in _named_entities("PEEP: A Browser RAT Posing as a Chrome Extension")


def test_all_caps_scan_is_confined_to_sentences_naming_a_category():
    """Unbounded, this would report every acronym in the document."""
    assert _named_entities("The SIEM ingested EVENTS from the estate.") == []


def test_ordinary_protocol_acronyms_are_not_families():
    assert _named_entities("The loader used HTTP and SOCKS5 with HVNC.") == []


def test_short_acronyms_are_excluded_by_length():
    """CVE, DNS, API and RAT are three characters; the length floor keeps them
    out without needing to enumerate them."""
    assert _named_entities("The RAT used DNS and an API for its backdoor.") == []


def test_established_extraction_still_works():
    assert _named_entities("The Chrysalis backdoor beacons to C2.") == ["Chrysalis"]
    assert _named_entities("PlugX implant seen.") == ["PlugX"]
    assert _named_entities("Attributed to APT41 and UNC2452.") == ["APT41", "UNC2452"]
    assert _named_entities("PureRAT was dropped.") == ["PureRAT"]


def test_a_plural_category_noun_still_collocates():
    assert "Chrysalis" in _named_entities("Chrysalis backdoors were deployed.")


def test_our_own_draft_marker_is_not_a_malware_name():
    """The hunt template's "DRAFT" sits in a title line that also names a
    category, so it was reported UNSUPPORTED on every generated draft -- a
    false fabrication alarm on the audit's own scaffolding."""
    title = "DRAFT - Indicators published in OSINT - New Arena Crysis Ransomware Variant Released"
    found = _named_entities(title)
    assert "DRAFT" not in found
    assert "Crysis" in found


def test_the_provider_label_is_not_a_malware_name():
    found = _named_entities("MISP Event: KadNap botnet IOC")
    assert "MISP" not in found
    assert "KadNap" in found
