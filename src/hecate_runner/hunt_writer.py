"""Render draft hunt markdown files into the ATHF workspace.

Kept separate from the orchestrator so we can unit-test rendering without any
subprocess or filesystem side effects other than writing the final file.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.athf_client import HypothesisResult
from hecate_runner.atomic_write import atomic_write_text

log = logging.getLogger(__name__)


@dataclass
class DraftHuntRequest:
    hunt_id: str
    threat_intel: str
    hypothesis: HypothesisResult
    generated_at: datetime
    research_id: str | None = None
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    source_url: str = ""
    related_hunts: list[str] = field(default_factory=list)
    # Sigma rules drafted for this hunt, as
    # {"logsource_category", "title", "level", "techniques", "rule_yaml"}.
    # Empty renders the same "human to draft" placeholder as before, so a
    # generation failure degrades to the old behavior rather than to a hunt
    # that looks like it has queries and does not.
    sigma_rules: list[dict[str, Any]] = field(default_factory=list)
    sigma_rule_dir: str = ""
    #: Rendered grounding audit (see grounding.py). Empty renders nothing, so
    #: a draft written before the audit runs is simply missing the section
    #: rather than claiming a clean result it never computed.
    grounding_section: str = ""


@contextmanager
def hunt_id_lock(hunts_root: Path) -> Iterator[None]:
    """Serialize the "compute next hunt ID, then write that file" critical
    section across processes.

    Without this, two overlapping `hecate-runner run` invocations (a manual run
    while the hourly timer also fires, or two cycles overlapping because one
    ran long) can both call next_hunt_id() before either has written its
    file, both compute the same H-00NN, and the second write silently
    clobbers the first draft's content -- different hypothesis, different
    CTI grounding -- with no error, even though the first draft's
    quota/notification had already fired for content that's now gone.

    Callers must call next_hunt_id() AND write_draft() (or draft_hunt_path()
    + the write) both inside this context -- allocating the ID outside the
    lock (or releasing it between allocation and write) defeats the point.
    """
    hunts_root.mkdir(parents=True, exist_ok=True)
    lock_path = hunts_root / ".hunt_id.lock"
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


# Persisted high-water mark for allocated hunt IDs, kept in hunts/ beside the
# lock file. The ID used to be derived purely by scanning hunts/ for the
# highest H-XXXX still present, which made it a function of what happened to
# be on disk rather than of what had ever been allocated. Committing the
# drafts away -- the normal way this workspace is cleaned up -- emptied the
# directory, so the next cycle restarted at H-0001 and reused IDs that
# already named a completely different hunt in git history (two unrelated
# drafts both claiming `hunt_id: H-0001`, one of them only recoverable from
# a commit). The counter records the highest ID ever handed out, so numbering
# survives the directory being emptied.
_COUNTER_FILENAME = ".hunt_id_counter"

# Bound the one-off git seed scan below so a large or damaged repo can not
# wedge a hunt cycle behind it.
_GIT_SEED_TIMEOUT_SEC = 30


def _max_hunt_id_on_disk(hunts_root: Path) -> int:
    """Highest H-XXXX currently written under the workspace, or 0."""
    max_id = 0
    if hunts_root.exists():
        for md in hunts_root.rglob("H-*.md"):
            m = re.match(r"H-(\d+)", md.stem)
            if m:
                max_id = max(max_id, int(m.group(1)))
    # Also check the flat hunts/ dir if it exists (some ATHF workspaces put
    # hunts at the root of the hunts/ directory)
    for candidate in hunts_root.parent.glob("H-*.md"):
        m = re.match(r"H-(\d+)", candidate.stem)
        if m:
            max_id = max(max_id, int(m.group(1)))
    return max_id


def _max_hunt_id_in_git(hunts_root: Path) -> int:
    """Highest H-XXXX ever committed under `hunts_root`, or 0.

    Seeds the counter on the first cycle after it was introduced, so
    numbering resumes past every draft git remembers instead of restarting
    underneath drafts that were committed and then cleaned off disk.
    `--name-only` over `--all` lists paths from every commit on every branch,
    which includes files that were added and later deleted -- exactly the
    ones a disk scan can no longer see.

    Returns 0 (and lets the on-disk floor stand) when the workspace is not a
    git repo, git is not installed, or the scan fails or times out. A missing
    seed only risks reusing an ID that is already unreachable on disk, so it
    is not worth failing a hunt cycle over.
    """
    try:
        proc = subprocess.run(
            ["git", "log", "--all", "--pretty=format:", "--name-only", "--", hunts_root.name],
            cwd=hunts_root.parent,
            capture_output=True,
            text=True,
            timeout=_GIT_SEED_TIMEOUT_SEC,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        log.warning("Could not scan git history to seed the hunt ID counter; using on-disk max")
        return 0
    if proc.returncode != 0:
        return 0
    max_id = 0
    for m in re.finditer(r"H-(\d+)\.md", proc.stdout):
        max_id = max(max_id, int(m.group(1)))
    return max_id


def _read_counter(counter_path: Path) -> int:
    """Read the persisted high-water mark, or 0 if it is absent/unusable."""
    try:
        return int(counter_path.read_text().strip())
    except (OSError, ValueError):
        # Absent, unreadable, or corrupted by a hand-edit. Treat it as "no
        # counter" and let the on-disk and git floors carry the value rather
        # than crashing the cycle; the counter is rewritten below regardless.
        return 0


def next_hunt_id(hunts_root: Path) -> str:
    """Allocate the next hunt ID and persist it as the new high-water mark.

    Must be called inside :func:`hunt_id_lock`: this both reads and writes
    the counter, and the read-modify-write is only safe while that lock is
    held.

    The ID is burned at allocation time, before the draft is written -- a
    cycle that dies between the two leaves a gap in the numbering rather
    than handing the same ID to the next cycle.
    """
    counter_path = hunts_root / _COUNTER_FILENAME
    # The on-disk max is always a floor, so drafts added by hand or by an
    # older hecate-runner since the last allocation still can not be clobbered.
    high_water = _max_hunt_id_on_disk(hunts_root)
    if counter_path.exists():
        high_water = max(high_water, _read_counter(counter_path))
    else:
        high_water = max(high_water, _max_hunt_id_in_git(hunts_root))
    allocated = high_water + 1
    atomic_write_text(counter_path, f"{allocated}\n")
    return f"H-{allocated:04d}"


def draft_hunt_path(hunts_root: Path, hunt_id: str, when: datetime) -> Path:
    year = when.strftime("%Y")
    quarter = f"Q{(when.month - 1) // 3 + 1}"
    return hunts_root / year / quarter / f"{hunt_id}.md"


# Frontmatter `title:` is a single YAML scalar line; keep it well clear of
# the ~1000-char per-line lint some tooling enforces on frontmatter, while
# still reading as an actual sentence rather than the ~80-char hard cut this
# replaced, which routinely sliced mid-word ("...on high-valu") with no
# ellipsis, silently presenting a truncated fragment as if it were complete.
_TITLE_MAX_LEN = 100


def _short_title(hypothesis: str) -> str:
    text = (hypothesis or "Untitled draft").strip()
    if len(text) <= _TITLE_MAX_LEN:
        return text
    truncated = text[:_TITLE_MAX_LEN]
    if " " in truncated:
        truncated = truncated.rsplit(" ", 1)[0]
    return truncated + "..."


def _able_cell(value: str) -> str:
    """Render one ABLE Scoping table cell.

    Falls back to the same "[Review CTI and populate]" placeholder the
    table always showed when the hypothesis-generator left the field empty
    (no LLM, or the model didn't find grounding for it in the CTI) --
    honest about the gap rather than fabricating a value. `|` is escaped
    since it's the markdown table cell delimiter; a hypothesis-generator
    field containing one would otherwise silently break the table layout.
    """
    text = value.strip()
    if not text:
        return "[Review CTI and populate]"
    return text.replace("|", "\\|")


def _draft_tags(is_threat_report: bool, is_indicator_only: bool = False) -> list[str]:
    """Frontmatter `tags:` for a draft, with `low-confidence-source`
    appended when the hypothesis-generator judged the CTI itself doesn't
    describe real adversary behavior -- lets `athf hunt search`/filtering
    surface (or exclude) these during triage instead of a reviewer having
    to open every draft to notice the banner in the body.

    `indicator-sweep` marks the other kind of thin source: a narrative-free
    feed dump, which produces an indicator-presence draft rather than a
    behavioral hypothesis. Distinct from `low-confidence-source` on purpose
    -- a feed dump is genuine threat intel, just not a story, and conflating
    the two would dilute what the low-confidence tag means at triage.
    """
    tags = ["draft", "auto-generated", "requires-human-review"]
    if not is_threat_report:
        tags.append("low-confidence-source")
    if is_indicator_only:
        tags.append("indicator-sweep")
    return tags


def _research_link_target(research_id: str, when: datetime) -> str:
    """Return the draft-relative path to a research doc.

    Derived from :func:`draft_hunt_path` rather than hardcoded: the depth of a
    draft below the workspace root is a property of that layout, and the two
    had drifted apart. drafts live at ``hunts/<year>/<quarter>/H-XXXX.md`` (3
    levels down) while the link said ``../../../../``, which resolved outside
    the workspace entirely and left every generated hunt pointing at a
    nonexistent file. The actual hunts_root value cancels out, so a nominal
    one is enough to measure the depth.
    """
    nominal_root = Path("/workspace/hunts")
    draft = draft_hunt_path(nominal_root, "H-0000", when)
    research = nominal_root.parent / "research" / f"{research_id}.md"
    return os.path.relpath(research, draft.parent)


def _research_document_line(req: DraftHuntRequest) -> str:
    """Render the Threat Intel & Research bullet naming the research doc.

    An indicator sweep gets its own wording rather than the generic "grounding
    unavailable": research is deliberately skipped for those, not failed, and
    the old line read like something had gone wrong. The alternative -- running
    research anyway -- produced documents whose every section said it had
    nothing to say, linked from here as "detailed pre-hunt research".
    """
    if req.research_id:
        target = _research_link_target(req.research_id, req.generated_at)
        return f"- **Research Document:** See [{req.research_id}]({target}) for detailed pre-hunt research"
    if req.hypothesis.is_indicator_only:
        return (
            "- **Research Document:** None — an indicator sweep needs no research "
            "grounding; the CTI's own indicator list is the hunt"
        )
    return "- **Research Document:** None — research grounding unavailable this cycle, review CTI directly"


def _render_sigma_section(req: DraftHuntRequest) -> str:
    """Render the drafted Sigma rules, or the old placeholder if there are none.

    Rules are shown in full rather than linked. An operator reviewing this
    hunt has to be able to judge the detection logic here, before advancing
    the status -- making them open five files elsewhere to do it is how
    review turns into rubber-stamping. The files still exist alongside, and
    are what `sigma convert` reads.
    """
    if not req.sigma_rules:
        return (
            "#### Initial Query\n\n"
            "```\n"
            "[Human to draft based on Observe section - no rules were generated "
            "for this hunt]\n"
            "```\n"
        )

    parts = [
        f"> {len(req.sigma_rules)} Sigma rule(s) auto-drafted from the source intelligence, "
        "one per applicable log source.",
        "> **Unreviewed.** Sigma is platform-neutral: convert with "
        "`sigma convert -t <backend>` once a target is chosen. Field names and "
        "false positives are the model's proposal and must be checked against "
        "real telemetry before anything is run.",
    ]
    if req.sigma_rule_dir:
        parts.append(f">\n> Rule files: `{req.sigma_rule_dir}`")
    parts.append("")

    for rule in req.sigma_rules:
        category = str(rule.get("logsource_category", "unknown"))
        title = str(rule.get("title", "Untitled rule"))
        level = str(rule.get("level", "medium"))
        techniques = ", ".join(str(t) for t in rule.get("techniques") or []) or "unmapped"
        parts.append(f"#### {category} - {title}")
        parts.append("")
        parts.append(f"*Severity:* {level} | *ATT&CK:* {techniques}")
        parts.append("")
        parts.append("```yaml")
        parts.append(str(rule.get("rule_yaml", "")).rstrip())
        parts.append("```")
        parts.append("")

    return "\n".join(parts)


def render_draft(req: DraftHuntRequest) -> str:
    """Return the full markdown content for a draft hunt."""
    hyp = req.hypothesis
    # Frontmatter carries only real, validated values; an unmapped field is
    # left empty rather than filled with a stand-in. "TXXXX" and
    # "unclassified" used to sit here as "honest placeholders", but both are
    # checked by `athf hunt validate` against the ATT&CK matrix, so every
    # draft that hit this path was written already failing the framework's
    # own validator ("Unknown MITRE technique: TXXXX"). "TXXXX" also *looks*
    # like a real ATT&CK ID at a glance, which a word like "unclassified"
    # at least does not. The human-facing gap markers live in the rendered
    # body below, where a reviewer actually reads them.
    techniques = hyp.techniques
    tactics = req.tactics
    platforms = req.platforms
    # Body-only rendering of the same gap, for the reviewer rather than the
    # validator. An empty ", ".join() would render a bare dangling label.
    techniques_display = (
        ", ".join(techniques) if techniques else "[none mapped - human to populate]"
    )
    # An empty list is an honest gap the reviewer can see; a vendor name is a
    # fabricated answer to "what telemetry does this hunt need", and this
    # workspace has no CrowdStrike. The rendered body already shows "[TBD]"
    # for the same emptiness.
    data_sources = hyp.data_sources

    def bullets(items: list[str]) -> str:
        return "\n".join(f"- {i}" for i in items) if items else "- [TBD]"

    # YAML frontmatter — list fields serialized with json.dumps to get valid quoting
    frontmatter = (
        "---\n"
        f"hunt_id: {req.hunt_id}\n"
        f"title: DRAFT - {_short_title(hyp.hypothesis)}\n"
        "status: planning\n"
        f"date: {req.generated_at.strftime('%Y-%m-%d')}\n"
        "hunter: hecate-runner orchestrator (draft)\n"
        f"platform: {json.dumps(platforms)}\n"
        f"tactics: {json.dumps(tactics)}\n"
        f"techniques: {json.dumps(techniques)}\n"
        f"data_sources: {json.dumps(data_sources)}\n"
        + (f"spawned_from: {req.research_id}\n" if req.research_id else "")
        + f"related_hunts: {json.dumps(req.related_hunts)}\n"
        "findings_count: 0\n"
        "true_positives: 0\n"
        "false_positives: 0\n"
        "customer_deliverables: []\n"
        f"tags: {json.dumps(_draft_tags(hyp.is_threat_report, hyp.is_indicator_only))}\n"
        "---\n\n"
    )

    low_confidence_banner = (
        (
            "\n> **🚩 LOW-CONFIDENCE SOURCE:** The hypothesis-generator judged that the source CTI "
            "does not actually describe observed/reported adversary behavior (e.g. vendor/product "
            "marketing, a compliance announcement) -- this hypothesis is speculative, not derived "
            f"from a specific reported campaign. {hyp.low_confidence_reason or ''}".rstrip()
        )
        if not hyp.is_threat_report
        else ""
    )

    # OBSERVE mirrors the three subsections of ATHF's own HUNT_LOCK template.
    # It previously carried a fourth, "Known False Positives", and left "What
    # Normal Looks Like" as "[Human review required]" -- but the template
    # defines that section as "legitimate activity that might trigger false
    # positives", which is exactly what hyp.false_positives holds. So the most
    # useful section in the block sat empty while its content was rendered
    # under an invented heading below it. "Expected Observables" likewise
    # repeated hyp.observables verbatim from "What Suspicious Looks Like"; it
    # now carries only what is actually distinct, the data sources.
    body = f"""# {req.hunt_id}: DRAFT - Automated Hunt Draft

> **⚠️ This hunt was auto-generated by hecate-runner.**
> **Do not execute queries until a human reviews the Learn/Observe sections and advances the status.**
{low_confidence_banner}

**Hunt Metadata**

- **Date:** {req.generated_at.strftime("%Y-%m-%d")}
- **Hunter:** hecate-runner orchestrator (draft)
- **Status:** planning
- **MITRE ATT&CK:** {techniques_display}

---

## LEARN: Prepare the Hunt

### Hypothesis Statement

{hyp.hypothesis or "[Model produced no hypothesis - review CTI intake]"}

### Threat Context

Source CTI:

> {req.threat_intel[:2000].strip()}

### Justification

{hyp.justification or "[No justification generated]"}

### ABLE Scoping

| **Field**   | **Your Input** |
|-------------|----------------|
| **Actor** | {_able_cell(hyp.actor)} |
| **Behavior** | {_able_cell(hyp.behavior)} |
| **Location** | {_able_cell(hyp.location)} |
| **Evidence** | {_able_cell(hyp.evidence)} |

### Threat Intel & Research

- **MITRE ATT&CK Techniques:** {techniques_display}
- **CTI Sources & References:** {f"[{req.source_url}]({req.source_url})" if req.source_url else "[Review CTI and populate]"}
{_research_document_line(req)}

### Grounding

{req.grounding_section or "Not yet audited."}

### Related Tickets

| **Team** | **Ticket/Details** |
|----------|-------------------|
| **SOC/IR** | N/A (auto-generated) |

---

## OBSERVE: Expected Behaviors

### What Normal Looks Like

{bullets(hyp.false_positives)}

### What Suspicious Looks Like

{bullets(hyp.observables)}

### Expected Observables

- **Data Sources:** {", ".join(hyp.data_sources) or "[TBD]"}
- **Observables:** listed under "What Suspicious Looks Like" above

---

## CHECK: Execute & Analyze

### Data Source Information

- **Index/Data Source:** [Human to populate]
- **Time Range:** [Human to populate]
- **Events Analyzed:** 0 (draft - not yet executed)
- **Data Quality:** N/A

### Hunting Queries

{_render_sigma_section(req)}

---

## KEEP: Findings & Response

### Executive Summary

[To be completed after human review and execution]

### Findings

| **Finding** | **Ticket** | **Description** |
|-------------|-----------|-----------------|
| N/A | N/A | Draft only |

**True Positives:** 0
**False Positives:** 0

---

**Draft Created:** {req.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")} by hecate-runner
**Next Review:** [Human review required before status can advance to `in-progress`]
"""
    return frontmatter + body


def write_draft(req: DraftHuntRequest, hunts_root: Path) -> Path:
    """Render and write the draft. Returns the file path."""
    path = draft_hunt_path(hunts_root, req.hunt_id, req.generated_at)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_draft(req))
    log.info("Wrote draft hunt %s (%d bytes)", path, path.stat().st_size)
    return path


def utcnow() -> datetime:
    return datetime.now(UTC)
