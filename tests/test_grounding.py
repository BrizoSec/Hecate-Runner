"""Tests for the post-draft grounding audit.

The audit's value depends entirely on its false-positive rate. A reviewer who
sees a behavioural rule reported as a fabricated indicator learns to ignore
the section, at which point a real fabrication passes unnoticed -- so most of
these tests are about what it must *not* flag.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from hecate_runner.grounding import (
    TechniqueFact,
    _is_path_component,
    audit_draft,
    render_grounding_section,
    technique_lacks_evidence,
)

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


def test_technique_matched_in_the_source_wording_is_not_called_a_hypothesis_inference():
    """25 Sep: the trail said T1566 was "matched in the intel's wording", and
    the draft's table said "inferred by the hypothesis, not named by the
    source" -- the same run contradicting itself."""
    report = audit_draft(
        draft_text="T1566",
        cti_text=CTI,
        cti_techniques=CTI_TECHNIQUES,
        matched_techniques=["T1566"],
    )
    assert report.claims[0].status == "derived"
    assert "matched in the source's wording" in report.claims[0].note
    assert "hypothesis" not in report.claims[0].note


def test_technique_lacks_evidence_when_no_source_uses_its_name():
    # H-0015: T1078 Valid Accounts on a fake-website 0-day report.
    assert technique_lacks_evidence("T1078", ("Valid Accounts",), CTI)
    assert not technique_lacks_evidence("T1071.001", ("Web Protocols",), CTI + " web protocols")


@pytest.mark.parametrize(
    ("technique_id", "names", "source"),
    [
        # All three were dropped on the 25 Sep rerun though the intel said so.
        ("T1036", ("Masquerading",), "Victims received links disguised as images."),
        (
            "T1218",
            ("System Binary Proxy Execution",),
            "The chain used MSI installers and VB6 loaders.",
        ),
        ("T1685", ("Disable or Modify Tools",), "It also ships a driver to kill Elastic Endpoint."),
        # Variants of a name word still count.
        ("T1055.012", ("Process Hollowing", "Process Injection"), "It hollowed a signed binary."),
    ],
)
def test_a_technique_the_source_describes_in_its_own_words_is_evidenced(
    technique_id, names, source
):
    assert not technique_lacks_evidence(technique_id, names, source)


def test_a_word_that_merely_starts_with_the_name_word_is_not_evidence():
    """T1571 Non-Standard Port was kept on "the public portion of the VeloCloud
    Edge authentication certificates"."""
    source = "Attackers need access to the public portion of the Edge certificates."
    assert technique_lacks_evidence("T1571", ("Non-Standard Port",), source)
    assert not technique_lacks_evidence(
        "T1571", ("Non-Standard Port",), "C2 over ports 8443 and 9001."
    )


def test_technique_lacks_evidence_counts_the_research_text():
    assert not technique_lacks_evidence(
        "T1078", ("Valid Accounts",), CTI, research_text="the actor reused valid accounts"
    )


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


# --- Paths are not hostnames -----------------------------------------------


class TestPathComponentsAreNotDomains:
    """`/Applications/Safari.app` is a path, but the domain pattern matches only
    `Safari.app` and the separator falls outside the match, so a rule matching a
    process parent was reported as carrying a fabricated domain.

    Handled positionally rather than by adding `app` to the filename suffix
    list: `.app` resolves as a real TLD, and that list omits real TLDs so a
    fabricated C2 domain cannot hide behind one."""

    def test_the_production_false_positive_is_gone(self):
        report = audit_draft(
            draft_text=_rule(
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: macsync\n"
                "  filter:\n"
                "    ParentImage|contains: /Applications/Safari.app\n"
                "  condition: selection and not filter"
            ),
            cti_text=CTI,
        )
        assert [c.value for c in report.unsupported] == []

    def test_it_also_covers_suffixes_the_list_could_never_hold(self):
        """`.sh` resolves too, so the suffix list cannot suppress it."""
        report = audit_draft(
            draft_text=_rule(
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: /usr/local/bin/deploy.sh\n"
                "  condition: selection"
            ),
            cti_text=CTI,
        )
        assert [c.value for c in report.unsupported] == []

    def test_a_bare_domain_in_the_same_tld_is_still_flagged(self):
        """The blind spot this avoids: no suffix is exempted, only paths."""
        report = audit_draft(
            draft_text=_rule(
                "detection:\n"
                "  selection:\n"
                "    QueryName|contains: fabricated.app\n"
                "  condition: selection"
            ),
            cti_text=CTI,
        )
        assert [c.value for c in report.unsupported] == ["fabricated.app"]

    def test_a_url_host_is_still_a_host(self):
        report = audit_draft(
            draft_text=_rule(
                "detection:\n"
                "  selection:\n"
                "    url|contains: https://invented-c2.test/beacon\n"
                "  condition: selection"
            ),
            cti_text=CTI,
        )
        assert "invented-c2.test" in [c.value for c in report.unsupported]

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("ParentImage|contains: /Applications/Safari.app", True),
            ("Image|endswith: C:\\Tools\\thing.app", True),
            ("CommandLine|contains: /usr/local/bin/deploy.sh", True),
            ("references: https://evil.com/payload", False),
            ("url|contains: //cdn.evil.com/x", False),
            ("QueryName|contains: evil.app", False),
            ("DestinationHostname: mythic-c2.com", False),
        ],
    )
    def test_path_discrimination_cases(self, text, expected):
        import re

        pattern = re.compile(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
        )
        match = pattern.search(text)
        assert match is not None
        assert _is_path_component(text, match.start()) is expected


# --- Platform consistency ---------------------------------------------------


class TestTechniquePlatformMismatch:
    """A technique that exists but cannot occur on the platform the hunt scopes
    to is a real mapping in the wrong place, and it reads as evidence.
    Observed: T1059.003 (Windows Command Shell) attached to a macOS hunt, which
    graded as `inferred` and passed."""

    DRAFT = "Techniques: T1059.003, T1217, T1098 observed on the affected hosts."
    FACTS: ClassVar[dict[str, TechniqueFact]] = {
        "T1059.003": TechniqueFact(valid=True, platforms=("Windows",)),
        "T1217": TechniqueFact(valid=True, platforms=("Linux", "macOS", "Windows")),
        # Near-universal; the orchestrator records no platforms for these.
        "T1098": TechniqueFact(valid=True, platforms=()),
    }

    def _audit(self, scope):
        return audit_draft(
            draft_text=self.DRAFT,
            cti_text="macOS infostealer campaign",
            technique_facts=self.FACTS,
            hunt_platforms=scope,
        )

    def test_a_windows_only_technique_on_a_macos_hunt_is_flagged(self):
        unsupported = [c.value for c in self._audit(["macOS"]).unsupported]
        assert unsupported == ["T1059.003"]

    def test_the_note_names_both_sides(self):
        claim = next(c for c in self._audit(["macOS"]).unsupported if c.value == "T1059.003")
        assert "Windows" in claim.note
        assert "macOS" in claim.note

    def test_a_matching_platform_is_clean(self):
        assert self._audit(["Windows"]).unsupported == []

    def test_an_overlapping_platform_is_clean(self):
        """T1217 spans three platforms including macOS; overlap is enough."""
        report = self._audit(["macOS"])
        assert "T1217" not in [c.value for c in report.unsupported]

    def test_unknown_hunt_scope_flags_nothing(self):
        """An empty platform list is a gap signal, not a contradiction."""
        assert self._audit([]).unsupported == []

    def test_a_near_universal_technique_can_never_contradict(self):
        """Techniques ATT&CK lists on 8+ platforms carry no scoping signal and
        are recorded with no platforms upstream, so they must stay silent."""
        report = self._audit(["macOS"])
        assert "T1098" not in [c.value for c in report.unsupported]

    def test_an_invalid_id_still_wins_over_a_platform_mismatch(self):
        """A technique that does not exist is an invention, which is the more
        serious finding; it must not be relabelled as a platform problem."""
        report = audit_draft(
            draft_text="Technique T1059.003 applies.",
            cti_text="macOS campaign",
            technique_facts={"T1059.003": TechniqueFact(valid=False, platforms=("Windows",))},
            hunt_platforms=["macOS"],
        )
        claim = report.unsupported[0]
        assert "no such technique" in claim.note


class TestTechniqueNameSupport:
    """A real, platform-compatible technique can still be the wrong one.

    Observed on H-0002: a LabubaRAT report describing masquerading as NVIDIA
    software and abuse of Microsoft build utilities was mapped to T1027.004
    Compile After Delivery and T1055.012 Process Hollowing, and both passed
    as inferred.
    """

    LABUBA_CTI = (
        "Description: LabubaRAT is a Rust-based remote access trojan designed to "
        "masquerade as legitimate NVIDIA software. The delivery mechanism utilized "
        "the RAT's own JavaScript execution capability, abusing legitimate "
        "Microsoft build utilities."
    )
    FACTS: ClassVar[dict[str, TechniqueFact]] = {
        "T1027.004": TechniqueFact(
            names=("Compile After Delivery", "Obfuscated Files or Information")
        ),
        "T1055.012": TechniqueFact(names=("Process Hollowing", "Process Injection")),
        "T1036.005": TechniqueFact(
            names=("Match Legitimate Resource Name or Location", "Masquerading")
        ),
        "T1127.001": TechniqueFact(
            names=("MSBuild", "Trusted Developer Utilities Proxy Execution")
        ),
    }

    def _status(self, technique: str, cti: str = LABUBA_CTI, research: str = "") -> str:
        report = audit_draft(
            draft_text=f"techniques: {technique}",
            cti_text=cti,
            research_text=research,
            technique_facts=self.FACTS,
        )
        return report.claims[0].status

    def test_a_technique_no_source_describes_is_unsupported(self):
        assert self._status("T1055.012") == "unsupported"

    def test_a_generic_word_shared_with_the_source_is_not_support(self):
        """ "delivery" appears in the CTI; "compile" does not."""
        assert self._status("T1027.004") == "unsupported"

    def test_the_parent_name_supports_a_subtechnique(self):
        """T1036.005's own name is abstract; "masquerade" is the parent's word."""
        assert self._status("T1036.005") == "derived"

    def test_the_research_document_counts_as_support(self):
        assert self._status("T1055.012", research="The loader performs process hollowing.") == (
            "derived"
        )

    def test_report_wording_supports_an_abstractly_named_technique(self):
        """A DDoS write-up never says "Network Denial of Service" (H-0483)."""
        facts = {"T1498": TechniqueFact(names=("Network Denial of Service",))}
        report = audit_draft(
            draft_text="techniques: T1498",
            cti_text="The botnet implements 15 DDoS attack methods.",
            technique_facts=facts,
        )
        assert report.claims[0].status == "derived"

    def test_incidental_domain_and_control_words_are_not_support(self):
        """H-0007: T1207 Rogue Domain Controller passed on a macOS report that
        mentioned "provider domains" and "remote control"."""
        facts = {"T1207": TechniqueFact(names=("Rogue Domain Controller",))}
        report = audit_draft(
            draft_text="techniques: T1207",
            cti_text="Typosquatted provider domains delivered macOS backdoors for remote control.",
            technique_facts=facts,
        )
        assert report.claims[0].status == "unsupported"

    def test_incidental_module_and_extension_words_are_not_support(self):
        """H-0004: T1547.006 passed on "Go modules" and "Chrome extensions"."""
        facts = {
            "T1547.006": TechniqueFact(
                names=("Kernel Modules and Extensions", "Boot or Logon Autostart Execution")
            )
        }
        report = audit_draft(
            draft_text="techniques: T1547.006",
            cti_text="Spreads across npm, PyPI, Go modules, Packagist and Chrome extensions.",
            technique_facts=facts,
        )
        assert report.claims[0].status == "unsupported"

    def test_a_name_of_only_generic_words_is_not_judged(self):
        facts = {"T1204": TechniqueFact(names=("User Execution",))}
        report = audit_draft(
            draft_text="techniques: T1204", cti_text="nothing", technique_facts=facts
        )
        assert report.claims[0].status == "derived"

    def test_an_unresolved_name_is_not_judged(self):
        report = audit_draft(
            draft_text="techniques: T1055.012",
            cti_text=self.LABUBA_CTI,
            technique_facts={"T1055.012": TechniqueFact()},
        )
        assert report.claims[0].status == "derived"

    def test_a_source_asserted_technique_is_never_second_guessed(self):
        report = audit_draft(
            draft_text="techniques: T1055.012",
            cti_text=self.LABUBA_CTI,
            cti_techniques=["T1055.012"],
            technique_facts=self.FACTS,
        )
        assert report.claims[0].status == "asserted"


def test_a_three_keyword_name_needs_two_of_them_in_the_sources() -> None:
    """H-0019: T1092 kept on a Tox P2P C2 report because it said "communications"."""
    cti = "AvisLoader uses the Tox network for command-and-control communications."
    assert technique_lacks_evidence("T1092", ("Communication Through Removable Media",), cti)
    assert not technique_lacks_evidence(
        "T1092", ("Communication Through Removable Media",), cti + " Commands ride removable media."
    )


def test_a_short_name_still_needs_only_one_keyword() -> None:
    assert not technique_lacks_evidence(
        "T1547.009", ("Shortcut Modification",), "persistence via a shortcut in Startup"
    )


def test_a_three_keyword_name_is_kept_on_report_wording_alone() -> None:
    assert not technique_lacks_evidence(
        "T1218", ("System Binary Proxy Execution",), "the loader runs through rundll32"
    )


def test_container_does_not_match_contains() -> None:
    """H-0016: T1610 Deploy Container kept on a VeloCloud report that "contains" a flaw."""
    cti = "VeloCloud Orchestrator deployments contain a critical vulnerability."
    assert technique_lacks_evidence("T1610", ("Deploy Container",), cti)
    assert not technique_lacks_evidence(
        "T1610", ("Deploy Container",), "spawned a new containers stack"
    )
