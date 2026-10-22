"""Tests for retrospective auditing of hunt files already on disk.

Most of these guard the recovery step rather than the grading. An extractor
that silently returns nothing makes every hunt look ungrounded — or, worse,
makes a hunt with no recoverable CTI look clean because there were no claims
to check. That exact failure produced a false "asserted=0" reading during
development, so the cases below pin the real file shape.
"""

from __future__ import annotations

from pathlib import Path

from hecate_runner.hunt_audit import (
    audit_hunt_text,
    extract_cti_block,
    parse_hunt_file,
    replace_grounding_section,
    research_text_for,
    strip_grounding_section,
)

# The shape hunt_writer actually emits: only the first blurb line carries the
# markdown blockquote prefix, the rest are continuation lines.
HUNT = """---
hunt_id: H-0618
status: planning
techniques: ["T1071.001", "T1566"]
spawned_from: R-0615
---

# H-0618: DRAFT

### Threat Context

Source CTI:

> MISP Event: The Chrysalis Backdoor
Org: CUDESO
MITRE ATT&CK Techniques: T1071.001, T1005
Key indicators:
  hostname: api.wiresguard.com

### Justification

The Chrysalis backdoor beacons to C2.

### Grounding

> stale content from an older audit

| Claim | Type | Grounding |
|-------|------|-----------|
| `T9999` | technique | inferred |

### Related Tickets

| Team | Ticket |
"""


# --- CTI recovery ----------------------------------------------------------


def test_recovers_the_cti_blurb():
    cti = extract_cti_block(HUNT)
    assert cti.startswith("MISP Event: The Chrysalis Backdoor")
    assert "api.wiresguard.com" in cti
    # Stops at the next section rather than swallowing the whole document.
    assert "Justification" not in cti


def test_strips_the_blockquote_prefix_only_where_present():
    cti = extract_cti_block(HUNT)
    assert not cti.startswith("> ")
    assert "Org: CUDESO" in cti


def test_absent_marker_returns_empty_rather_than_guessing():
    """A fallback here would grade the hunt's claims against its own prose,
    marking everything asserted — a false clean bill of health."""
    assert extract_cti_block("# H-0001\n\nNo threat context section.\n") == ""


def test_facts_expose_whether_cti_was_recoverable():
    assert parse_hunt_file(HUNT).has_cti is True
    assert parse_hunt_file("# no context").has_cti is False


# --- Frontmatter -----------------------------------------------------------


def test_reads_hunt_and_research_ids():
    facts = parse_hunt_file(HUNT)
    assert facts.hunt_id == "H-0618"
    assert facts.research_id == "R-0615"


def test_ignores_a_frontmatter_key_that_only_appears_in_prose():
    text = "# Not frontmatter\n\nspawned_from: R-9999\n"
    assert parse_hunt_file(text).research_id == ""


def test_stops_reading_frontmatter_at_the_closing_fence():
    text = "---\nhunt_id: H-0001\n---\n\nspawned_from: R-9999\n"
    facts = parse_hunt_file(text)
    assert facts.hunt_id == "H-0001"
    assert facts.research_id == ""


def test_techniques_come_from_the_cti_not_the_frontmatter():
    """The asserted/derived split depends on what the *source* named. The
    frontmatter lists what the draft settled on, which includes inferences."""
    facts = parse_hunt_file(HUNT)
    assert facts.cti_techniques == ["T1071.001", "T1005"]
    assert "T1566" not in facts.cti_techniques


# --- Grounding section handling --------------------------------------------


def test_strips_the_previous_grounding_section_before_grading():
    """Otherwise the audit reads its own claim table as hunt content."""
    stripped = strip_grounding_section(HUNT)
    assert "stale content from an older audit" not in stripped
    assert "T9999" not in stripped
    # Everything around it survives.
    assert "### Related Tickets" in stripped
    assert "### Justification" in stripped


def test_stale_claims_do_not_reappear_in_a_fresh_audit():
    _, report = audit_hunt_text(HUNT)
    assert "T9999" not in {c.value for c in report.claims}


def test_replaces_the_grounding_section_in_place():
    updated = replace_grounding_section(HUNT, "> fresh result\n")
    assert "fresh result" in updated
    assert "stale content from an older audit" not in updated
    assert "### Related Tickets" in updated
    assert updated.startswith("---\nhunt_id: H-0618")


def test_replacement_is_idempotent():
    once = replace_grounding_section(HUNT, "> fresh result\n")
    twice = replace_grounding_section(once, "> fresh result\n")
    assert once == twice


def test_a_hunt_without_a_grounding_heading_is_left_alone():
    """Older drafts predate the section; inserting one would mean guessing
    where it belongs in a template that has since changed."""
    text = "---\nhunt_id: H-0001\n---\n\n### Justification\n\nprose\n"
    assert replace_grounding_section(text, "> fresh\n") == text


# --- Grading ---------------------------------------------------------------


def test_grades_against_the_recovered_cti():
    facts, report = audit_hunt_text(HUNT)
    assert facts.hunt_id == "H-0618"
    by_value = {c.value: c.status for c in report.claims}
    assert by_value["T1071.001"] == "asserted"
    assert by_value["T1566"] == "derived"
    assert by_value["Chrysalis"] == "asserted"


def test_research_context_does_not_corroborate_a_case_claim():
    hunt = HUNT.replace("The Chrysalis backdoor beacons", "The Nightshade backdoor beacons")
    _, without = audit_hunt_text(hunt)
    _, with_research = audit_hunt_text(hunt, research_text="Nightshade is a known implant")
    assert {c.value: c.status for c in without.claims}["Nightshade"] == "unsupported"
    assert {c.value: c.status for c in with_research.claims}["Nightshade"] == "unsupported"


# --- Research lookup -------------------------------------------------------


def test_research_text_is_read_from_the_workspace(tmp_path: Path):
    (tmp_path / "research").mkdir()
    (tmp_path / "research" / "R-0615.md").write_text("research body")
    assert research_text_for(tmp_path, "R-0615") == "research body"


def test_a_missing_research_document_is_not_an_error(tmp_path: Path):
    assert research_text_for(tmp_path, "R-9999") == ""
    assert research_text_for(tmp_path, "") == ""
