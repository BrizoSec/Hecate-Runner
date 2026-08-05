"""Render draft hunt markdown files into the ATHF workspace.

Kept separate from the orchestrator so we can unit-test rendering without any
subprocess or filesystem side effects other than writing the final file.
"""

from __future__ import annotations

import fcntl
import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sec7669.athf_client import HypothesisResult

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


@contextmanager
def hunt_id_lock(hunts_root: Path) -> Iterator[None]:
    """Serialize the "compute next hunt ID, then write that file" critical
    section across processes.

    Without this, two overlapping `sec7669 run` invocations (a manual run
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


def next_hunt_id(hunts_root: Path) -> str:
    """Find the highest H-XXXX under the workspace and return the next ID."""
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
    return f"H-{max_id + 1:04d}"


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


def _draft_tags(is_threat_report: bool) -> list[str]:
    """Frontmatter `tags:` for a draft, with `low-confidence-source`
    appended when the hypothesis-generator judged the CTI itself doesn't
    describe real adversary behavior -- lets `athf hunt search`/filtering
    surface (or exclude) these during triage instead of a reviewer having
    to open every draft to notice the banner in the body.
    """
    tags = ["draft", "auto-generated", "requires-human-review"]
    if not is_threat_report:
        tags.append("low-confidence-source")
    return tags


def render_draft(req: DraftHuntRequest) -> str:
    """Return the full markdown content for a draft hunt."""
    hyp = req.hypothesis
    techniques = hyp.techniques or ["TXXXX"]
    # Real tactics/platforms come from an ATT&CK lookup keyed off hyp.techniques
    # (see Orchestrator._resolve_ttps) — when that lookup found nothing (no
    # techniques to resolve, unknown ID, STIX unavailable), an explicit
    # "unclassified"/"Unknown" placeholder is honest about the gap instead of
    # defaulting to a fixed tactic/platform that's usually wrong for the CTI.
    tactics = req.tactics or ["unclassified"]
    platforms = req.platforms or ["Unknown"]
    data_sources = hyp.data_sources or ["CrowdStrike"]

    def bullets(items: list[str]) -> str:
        return "\n".join(f"- {i}" for i in items) if items else "- [TBD]"

    # YAML frontmatter — list fields serialized with json.dumps to get valid quoting
    frontmatter = (
        "---\n"
        f"hunt_id: {req.hunt_id}\n"
        f"title: DRAFT - {_short_title(hyp.hypothesis)}\n"
        "status: planning\n"
        f"date: {req.generated_at.strftime('%Y-%m-%d')}\n"
        "hunter: sec7669 orchestrator (draft)\n"
        f"platform: {json.dumps(platforms)}\n"
        f"tactics: {json.dumps(tactics)}\n"
        f"techniques: {json.dumps(techniques)}\n"
        f"data_sources: {json.dumps(data_sources)}\n"
        + (f"spawned_from: {req.research_id}\n" if req.research_id else "")
        + "related_hunts: []\n"
        "findings_count: 0\n"
        "true_positives: 0\n"
        "false_positives: 0\n"
        "customer_deliverables: []\n"
        f"tags: {json.dumps(_draft_tags(hyp.is_threat_report))}\n"
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

    body = f"""# {req.hunt_id}: DRAFT - Automated Hunt Draft

> **⚠️ This hunt was auto-generated by sec7669.**
> **Do not execute queries until a human reviews the Learn/Observe sections and advances the status.**
{low_confidence_banner}

**Hunt Metadata**

- **Date:** {req.generated_at.strftime('%Y-%m-%d')}
- **Hunter:** sec7669 orchestrator (draft)
- **Status:** planning
- **MITRE ATT&CK:** {", ".join(techniques)}

---

## LEARN: Prepare the Hunt

### Hypothesis Statement

{hyp.hypothesis or '[Model produced no hypothesis - review CTI intake]'}

### Threat Context

Source CTI:

> {req.threat_intel[:2000].strip()}

### Justification

{hyp.justification or '[No justification generated]'}

### ABLE Scoping

| **Field**   | **Your Input** |
|-------------|----------------|
| **Actor** | {_able_cell(hyp.actor)} |
| **Behavior** | {_able_cell(hyp.behavior)} |
| **Location** | {_able_cell(hyp.location)} |
| **Evidence** | {_able_cell(hyp.evidence)} |

### Threat Intel & Research

- **MITRE ATT&CK Techniques:** {", ".join(techniques)}
- **CTI Sources & References:** {f"[{req.source_url}]({req.source_url})" if req.source_url else "[Review CTI and populate]"}
{f"- **Research Document:** See [{req.research_id}](../../../../research/{req.research_id}.md) for detailed pre-hunt research" if req.research_id else "- **Research Document:** None — research grounding unavailable this cycle, review CTI directly"}

### Related Tickets

| **Team** | **Ticket/Details** |
|----------|-------------------|
| **SOC/IR** | N/A (auto-generated) |

---

## OBSERVE: Expected Behaviors

### What Normal Looks Like

[Human review required]

### What Suspicious Looks Like

{bullets(hyp.observables)}

### Expected Observables

- **Data Sources:** {", ".join(hyp.data_sources) or '[TBD]'}
- **Observables:**
{chr(10).join('  - ' + o for o in hyp.observables) if hyp.observables else '  - [TBD]'}

### Known False Positives

{bullets(hyp.false_positives)}

---

## CHECK: Execute & Analyze

### Data Source Information

- **Index/Data Source:** [Human to populate]
- **Time Range:** [Human to populate]
- **Events Analyzed:** 0 (draft - not yet executed)
- **Data Quality:** N/A

### Hunting Queries

#### Initial Query

```
[Human to draft based on Observe section - sec7669 DOES NOT auto-generate queries]
```

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

**Draft Created:** {req.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')} by sec7669
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
