"""Re-audit hunt files that already exist on disk.

The grounding audit runs while a hunt is being drafted, which leaves every
hunt written before a given version of the audit graded by an older one — or,
for anything drafted before the audit existed, not graded at all. This module
is the retrospective half: read a finished hunt, recover the evidence it was
built from, and grade it again.

The recovery is the delicate part, and it is deliberately dull. A throwaway
regex written to do this ad hoc silently matched nothing and reported a fully
grounded hunt as having zero asserted claims — a false clean bill of health,
which is worse than no audit. So the parsing here scans line by line, returns
explicitly empty results rather than guessing, and is tested against the real
file shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from hecate_agent.core.grounding import GroundingReport, TechniqueFact, audit_draft

from hecate_runner.cti import ATTACK_TECHNIQUE_LINE

#: The line hunt_writer emits immediately above the embedded CTI blurb.
_CTI_MARKER = "Source CTI:"

#: Only the blurb's first line carries the markdown blockquote prefix; the
#: rest are continuation lines, so the prefix is stripped per-line rather than
#: assumed present.
_QUOTE_PREFIX = "> "

_SECTION_PREFIX = "### "
_GROUNDING_HEADING = "### Grounding"
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class HuntFacts:
    """What a hunt file records about the evidence behind it."""

    hunt_id: str = ""
    research_id: str = ""
    cti_text: str = ""
    cti_techniques: list[str] = field(default_factory=list)

    @property
    def has_cti(self) -> bool:
        return bool(self.cti_text.strip())


def _frontmatter_value(lines: list[str], key: str) -> str:
    """Read one scalar out of the YAML frontmatter without a YAML parser.

    Only the first document block is considered, so a `spawned_from:` that
    appears later in prose cannot be mistaken for the real field.
    """
    if not lines or lines[0].strip() != "---":
        return ""
    prefix = f"{key}:"
    for line in lines[1:]:
        if line.strip() == "---":
            return ""
        if line.startswith(prefix):
            return line[len(prefix) :].strip().strip("\"'")
    return ""


def extract_cti_block(text: str) -> str:
    """Recover the CTI blurb a hunt was drafted from.

    Returns "" when the marker is absent — a hunt predating the Threat Context
    block, or one written by hand. An empty result must stay empty: inventing
    a fallback here would grade claims against the hunt's own prose, which
    would mark everything asserted.
    """
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == _CTI_MARKER)
    except StopIteration:
        return ""

    collected: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith(_SECTION_PREFIX):
            break
        collected.append(line[len(_QUOTE_PREFIX) :] if line.startswith(_QUOTE_PREFIX) else line)
    return "\n".join(collected).strip()


def parse_hunt_file(text: str) -> HuntFacts:
    """Pull the audit's inputs back out of a finished hunt file."""
    lines = text.splitlines()
    cti = extract_cti_block(text)

    # Techniques the *source* asserted, not the ones the draft settled on --
    # the distinction between "asserted" and "derived" depends on it.
    techniques: list[str] = []
    for line in cti.splitlines():
        if line.startswith(ATTACK_TECHNIQUE_LINE):
            techniques = _TECHNIQUE_RE.findall(line)
            break

    return HuntFacts(
        hunt_id=_frontmatter_value(lines, "hunt_id"),
        research_id=_frontmatter_value(lines, "spawned_from"),
        cti_text=cti,
        cti_techniques=techniques,
    )


def strip_grounding_section(text: str) -> str:
    """Remove the rendered Grounding section from a hunt's body.

    The audit must not read its own previous output: a claim table is full of
    the very identifiers the extractors look for, so leaving it in place would
    have the audit re-grade its own findings as hunt content.
    """
    lines = text.splitlines(keepends=True)
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == _GROUNDING_HEADING)
    except StopIteration:
        return text

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(_SECTION_PREFIX):
            end = index
            break
    return "".join([*lines[:start], *lines[end:]])


def replace_grounding_section(text: str, rendered: str) -> str:
    """Swap in a freshly rendered Grounding section, in place.

    Returns the text unchanged when the hunt has no Grounding heading — an
    older draft. Adding one would mean guessing where it belongs in a template
    that has since changed, and a re-audit is a reporting operation, not a
    migration.
    """
    lines = text.splitlines(keepends=True)
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == _GROUNDING_HEADING)
    except StopIteration:
        return text

    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(_SECTION_PREFIX):
            end = index
            break

    body = rendered if rendered.endswith("\n") else rendered + "\n"
    return "".join([*lines[: start + 1], "\n", body, "\n", *lines[end:]])


def audit_hunt_text(
    text: str,
    *,
    research_text: str = "",
    technique_facts: dict[str, TechniqueFact] | None = None,
) -> tuple[HuntFacts, GroundingReport]:
    """Grade one hunt's claims against the evidence recorded inside it."""
    facts = parse_hunt_file(text)
    report = audit_draft(
        draft_text=strip_grounding_section(text),
        cti_text=facts.cti_text,
        research_text=research_text,
        cti_techniques=facts.cti_techniques,
        technique_facts=technique_facts,
    )
    return facts, report


def research_text_for(workspace: Path, research_id: str) -> str:
    """The research document behind a hunt, or "" when there is none.

    Research is secondary evidence (see grounding.py), so a missing document
    only costs a claim its `corroborated` grade — it never turns an asserted
    claim unsupported.
    """
    if not research_id:
        return ""
    try:
        return (workspace / "research" / f"{research_id}.md").read_text(encoding="utf-8")
    except OSError:
        return ""
