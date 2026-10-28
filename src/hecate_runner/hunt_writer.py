"""Render draft hunt markdown files into the Hecate workspace.

Kept separate from the orchestrator so we can unit-test rendering without any
subprocess or filesystem side effects other than writing the final file.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.hecate_client import HypothesisResult

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
    #: Primary-source evidence (hecate_agent.core.source_evidence.SourceEvidence
    #: .to_dict()) and the feed's indicators typed against it
    #: (IndicatorRecord dicts). Empty renders no evidence section.
    source_evidence: dict[str, Any] = field(default_factory=dict)
    indicator_records: list[dict[str, Any]] = field(default_factory=list)
    #: Quality of the research context's web search, shown next to its link.
    #: Empty when no research ran.
    research_grounding: str = ""
    #: Supporting passage per technique (TechniqueEvidence dicts from the
    #: orchestrator), including techniques dropped as capability-only.
    technique_evidence: list[dict[str, Any]] = field(default_factory=list)
    #: What the claim audit removed or rewrote (hecate_agent.core.claim_audit
    #: ClaimFinding dicts). Rendered under Grounding, so the quoted originals
    #: are shown as audit record, not as the draft's own claims.
    claim_audit: list[dict[str, Any]] = field(default_factory=list)
    #: The source's detection guidance (GuidanceItem dicts): each item quoted,
    #: with the telemetry that can see it and the rule drafted from it.
    detection_guidance: list[dict[str, Any]] = field(default_factory=list)
    #: Behaviours the rule reviewer found no rule for, each with its verified quote.
    review_gaps: list[dict[str, str]] = field(default_factory=list)
    #: Purple-team replay (hecate_runner.purple_team): rules that had source
    #: events to replay, rules that matched them and no benign event, rules
    #: tuned, and the number of synthesised events.
    purple_team_rules_evaluated: int = 0
    purple_team_rules_validated: int = 0
    purple_team_rules_tuned: int = 0
    purple_team_telemetry_count: int = 0
    purple_team_atomic_techniques: list[str] = field(default_factory=list)
    purple_team_atomic_tests: list[dict[str, str]] = field(default_factory=list)
    #: Closed-loop live adversary emulation & breach simulation (BAS) verification results
    bas_verification: dict[str, Any] | None = None
    #: Claim excerpts and exact source passages checked by the Runner.
    claim_evidence: list[dict[str, str]] = field(default_factory=list)


#: Ceiling on the CTI blurb embedded in a draft. Generous on purpose: the
#: providers already bound what they emit (MISP inlines at most 40 attributes,
#: OTX 40 indicators, both at 120 chars each), so their worst case is ~8k and
#: this should never bite in practice.
#:
#: It used to be 2,000, which was below both. The blurb was then silently cut
#: mid-indicator-list, and because `hunt_audit` re-derives the CTI from this
#: embedded copy, every indicator past the cut was re-graded UNSUPPORTED --
#: real C2 domains reported as fabrications on H-0007 and H-0010. A false
#: fabrication alarm is the one thing the grounding audit must not produce,
#: so if this ever does truncate it says so in the text rather than leaving
#: the audit to draw the wrong conclusion from silence.
_MAX_EMBEDDED_CTI = 10_000


def embedded_cti(threat_intel: str) -> str:
    """The CTI blurb as it is quoted into a draft."""
    text = (threat_intel or "").strip()
    if len(text) <= _MAX_EMBEDDED_CTI:
        return text
    omitted = len(text) - _MAX_EMBEDDED_CTI
    return (
        text[:_MAX_EMBEDDED_CTI].rstrip()
        + f"\n[... {omitted} characters of CTI omitted from this draft. "
        "Indicators below this point were available to drafting but are not "
        "quoted here, so a grounding audit cannot confirm them.]"
    )


# Hunt ID allocation (hunt_id_lock, next_hunt_id) lives in hecate_agent.core.hunt_ids,
# shared with the Hecate-Core CLI, MCP tools and LangGraph orchestrator, which all
# write the same hunts/ directory. Callers must allocate AND write the draft inside
# hunt_id_lock, exactly as before.


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


def _title_scalar(hypothesis: str) -> str:
    """The `title:` value, quoted so it is always a valid YAML scalar.

    Every list field here goes through ``json.dumps`` for exactly this
    reason; the title was the one interpolated bare, and a hypothesis
    carrying a colon broke the frontmatter of the whole hunt. H-0002 was
    drafted from an ESET event titled "MoustachedBouncer: Espionage against
    foreign diplomats" and came out as::

        title: DRAFT - Indicators published in MoustachedBouncer: Espionage ...

    which YAML reads as a second mapping value and rejects. `hecate-agent
    hunt validate` then failed on the file, so the draft was unparseable by
    the very tooling meant to check it.

    A JSON string is a valid YAML double-quoted scalar, so this also covers
    embedded quotes and backslashes. ``ensure_ascii=False`` keeps non-ASCII
    titles readable rather than escaping them to \\uXXXX.
    """
    return json.dumps(f"DRAFT - {_short_title(hypothesis)}", ensure_ascii=False)


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
    describe real adversary behavior -- lets `hecate-agent hunt search`/filtering
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
        grounding = f" ({req.research_grounding})" if req.research_grounding else ""
        return f"- **Research Context:** See [{req.research_id}]({target}) for background leads{grounding}"
    if req.hypothesis.is_indicator_only:
        return (
            "- **Research Context:** None — an indicator sweep needs no research "
            "grounding; the CTI's own indicator list is the hunt"
        )
    return "- **Research Context:** None — review the CTI directly"


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

    replay = [r.get("purple_team") or {} for r in req.sigma_rules]
    validated = sum(1 for r in replay if r.get("validated"))
    replayed = sum(1 for r in replay if r.get("status") and r.get("status") != "no_replay_events")
    parts = [
        f"> {len(req.sigma_rules)} Sigma rule(s) auto-drafted from the source intelligence, "
        "one per applicable log source.",
    ]
    if replayed:
        if req.purple_team_atomic_techniques:
            emulated_str = ", ".join(f"`{t}`" for t in req.purple_team_atomic_techniques[:4])
            parts.append(
                f"> **Adversary Emulation (Atomic Red Team):** {validated} of {replayed} evaluated rule(s) validated "
                f"against dynamic adversary emulation telemetry across {emulated_str} and none of the benign baseline."
            )
        else:
            parts.append(
                f"> **Purple-team replay:** {validated} of {replayed} replayed rule(s) matched events synthesised "
                "from the report's own artifacts and none of a small benign sample"
                + (
                    f"; {len(req.sigma_rules) - replayed} had no source artifact to replay"
                    if replayed < len(req.sigma_rules)
                    else ""
                )
                + ". A replay of what the report names, not emulation: it shows a rule can match the "
                "described activity, not that it is quiet in your environment."
            )
    parts.append(
        "> **Unreviewed.** Sigma is platform-neutral: convert with "
        "`sigma convert -t <backend>` once a target is chosen. Field names and "
        "false positives are the model's proposal and must be checked against "
        "real telemetry before anything is run."
    )
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

        ryaml = str(rule.get("rule_yaml", "")).strip()
        if ryaml:
            try:
                from hecate_agent.api import transpile_sigma_rule

                t_queries = transpile_sigma_rule(ryaml)
                successful_t = [
                    t
                    for t in t_queries.values()
                    if getattr(t, "success", False) and getattr(t, "query", None)
                ]
                if successful_t:
                    parts.append("##### Native EDR & SIEM Queries")
                    parts.append("")
                    for t_item in successful_t:
                        code_lang = (
                            "kql"
                            if t_item.dialect == "kql"
                            else ("text" if t_item.dialect in {"leql", "s1ql"} else t_item.dialect)
                        )
                        parts.append(f"**{t_item.platform_name} ({t_item.dialect.upper()}):**")
                        parts.append(f"```{code_lang}")
                        parts.append(t_item.query.strip())
                        parts.append("```")
                        parts.append("")
            except Exception:
                pass

    return "\n".join(parts)


_RULE_PLACEMENT_NOTE = {
    "archive": "none: an archive never runs as a process",
    "document": "none: a document is not a process image",
    "script": "none: a script runs as its interpreter, which carries the interpreter's hash",
    "network_content": "none: network content, not a file on disk",
    "memory_only": "none: exists only in memory",
    "historical": "none: historical, not this intrusion",
    "non_file": "none: a token, key or certificate fingerprint, not the hash of a file",
    "target": "none: an address the actor targeted, not infrastructure a host connects to",
}


def _rule_placements(record: dict[str, Any]) -> str:
    """The log sources a record's rules go to, from the same routing the Sigma stage uses.

    Restating the routing here drifted from it: inbound attack sources were
    listed as outbound network_connection, and bare dual-use URL paths as proxy.
    """
    from hecate_agent.core.provenance import IndicatorRecord, placements

    placed = placements(IndicatorRecord.from_dict(record))
    if not placed:
        role = str(record.get("role", ""))
        if record.get("status") == "historical":
            role = "historical"
        return _RULE_PLACEMENT_NOTE.get(role, "none: no log records it in this role")
    ports = ", ".join(str(p) for p in record.get("ports") or [])
    categories = dict.fromkeys(p.split(".")[0] for p in placed)
    return ", ".join(
        f"{c} on {ports}" if ports and c == "network_connection" else c for c in categories
    )


def _cell(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _render_source_evidence(req: DraftHuntRequest) -> str:
    """The primary report's verified artifacts and each indicator's role, as the draft's own content."""
    ev = req.source_evidence
    if not ev:
        return ""
    url = ev.get("url", "")
    if ev.get("error") and not ev.get("artifacts"):
        return f"### Primary Source Evidence\n\nNot extracted from {url}: {_cell(ev['error'])}\n\n"
    lines = [
        "### Primary Source Evidence",
        "",
        f"Extracted from [{url}]({url}) ({ev.get('chars', 0):,} characters). Artifacts in the first table "
        "were verified verbatim in the report. Feed indicators are listed separately; only indicators "
        "with a quoted evidence passage are verified against this report. This is the report's account, "
        "not independent confirmation.",
        "",
    ]
    behaviours = [a for a in ev.get("artifacts", []) if a.get("kind") not in _INDICATOR_KINDS]
    if behaviours:
        lines += ["| Artifact | Kind | Role | Status | Evidence |", "|---|---|---|---|---|"]
        for a in behaviours:
            evidence = f'"{_cell(a["evidence"])}"' if a.get("evidence") else "unverified"
            lines.append(
                f"| `{_cell(a['value'], 90)}` | {a['kind']} | {_cell(a['role'], 40)} | {a['status']} | {evidence} |"
            )
        lines.append("")
    records = req.indicator_records
    if records:
        lines += [
            "**Indicators by role** (the feed's indicators, typed against the report):",
            "",
            "| Indicator | Type | Role | Status | Confidence | Rules | Evidence |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in records:
            evidence = f'"{_cell(r["evidence"])}"' if r.get("evidence") else "unverified"
            lines.append(
                f"| `{_cell(r['value'], 70)}` | {r['type']} | {r.get('role', 'unknown')} | "
                f"{r.get('status', 'unknown')} | {r.get('confidence', 'unknown')} | {_rule_placements(r)} | "
                f"{evidence} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_claim_audit(req: DraftHuntRequest) -> str:
    """Every observable the audit removed and every sentence it rewrote, with the reason."""
    if not req.claim_audit:
        return ""
    lines = ["", "", "#### Claim Audit", ""]
    for f in req.claim_audit:
        lines.append(
            f'- {f["action"]} ({f["field"]}): "{_cell(f["text"], 200)}" - {_cell(f["reason"], 160)}'
        )
    return "\n".join(lines)


def _render_claim_evidence(req: DraftHuntRequest) -> str:
    """Show quote provenance for generated claims, including missing links."""
    if not req.claim_evidence:
        return ""
    lines = [
        "",
        "#### Claim Evidence References",
        "",
        "The Runner checks that each quote occurs in the source text and that the cited claim excerpt appears in the final field. "
        "A text match does not prove the quote supports the claim; review that relationship.",
        "",
        "| Field | Claim excerpt | Source passage | Quote check |",
        "|---|---|---|---|",
    ]
    for row in req.claim_evidence:
        quote = f'"{_cell(row.get("quote", ""), 220)}"' if row.get("quote") else "—"
        source = row.get("source", "")
        source_link = (
            f"[{_cell(source, 100)}]({source})"
            if source.startswith(("https://", "http://"))
            else _cell(source, 100) or "—"
        )
        lines.append(
            f"| {row.get('field', '')} | {_cell(row.get('claim', ''), 180)} | {quote} | "
            f"{_cell(row.get('status', ''), 80)} ({source_link}) |"
        )
    return "\n".join(lines) + "\n"


_GUIDANCE_ROUTES = {
    "sigma": "Sigma",
    "edr": "EDR query",
    "network-content": "IDS/NDR signature",
    "indicator": "IOC sweep",
    "review": "Review",
}


def _render_review_gaps(req: DraftHuntRequest) -> str:
    """Behaviours the reviewer found no rule for, quoted from the hypothesis or the source."""
    if not req.review_gaps:
        return ""
    lines = ["", "", "#### Not Covered by Any Rule (rule review)", ""]
    for gap in req.review_gaps:
        lines.append(
            f'- {_cell(gap.get("behaviour", ""), 160)}: "{_cell(gap.get("quote", ""), 200)}"'
        )
    return "\n".join(lines)


def _render_detection_guidance(req: DraftHuntRequest) -> str:
    """The source's own detection guidance, each item routed to the telemetry that can see it."""
    if not req.detection_guidance:
        return ""
    source = next((g.get("source") for g in req.detection_guidance if g.get("source")), "")
    titles = [str(r.get("title", "")) for r in req.sigma_rules]
    lines = [
        "### Detection Guidance from the Source",
        "",
        f"Quoted from the detection section of {source}."
        if source
        else "Quoted from the source's detection section.",
        "",
        "| ID | Guidance | Runs in | Analytic |",
        "|---|---|---|---|",
    ]
    for g in req.detection_guidance:
        route = str(g.get("route", "review"))
        if route == "sigma":
            drafted = [
                t.split(": ", 1)[-1]
                for t in titles
                if t.startswith(f"Source guidance {g.get('id')}:")
            ]
            analytic = "; ".join(drafted) if drafted else "no rule drafted; write one by hand"
        elif route == "indicator":
            analytic = "covered by the IOC rules"
        else:
            analytic = str(g.get("reason", ""))
        lines.append(
            f'| {g.get("id")} | "{_cell(str(g.get("text", "")), 200)}" | {_GUIDANCE_ROUTES.get(route, route)} | '
            f"{_cell(analytic, 160)} |"
        )
    return "\n".join(lines) + "\n\n"


def _render_technique_evidence(req: DraftHuntRequest) -> str:
    """Why each technique is mapped, and which were left out as capability only."""
    rows = [e for e in req.technique_evidence if e.get("status") != "capability"]
    capability = [e for e in req.technique_evidence if e.get("status") == "capability"]
    if not rows and not capability:
        return ""
    lines = ["", "#### Technique Evidence", ""]
    if rows:
        lines += ["| Technique | Status | Evidence | Source |", "|---|---|---|---|"]
        for e in rows:
            passage = f'"{_cell(e["passage"], 220)}"' if e.get("passage") else "—"
            basis = f" ({_cell(e['behaviour'], 40)})" if e.get("behaviour") else ""
            lines.append(
                f"| {e['technique_id']} | {e.get('status', '')} | {passage}{basis} | {e.get('source', '')} |"
            )
    if capability:
        lines += [
            "",
            "Not mapped, capability only (the source describes what a tool can do, not what happened):",
            "",
        ]
        for e in capability:
            lines.append(f'- {e["technique_id"]}: "{_cell(e.get("passage", ""), 220)}"')
    return "\n".join(lines) + "\n"


_INDICATOR_KINDS = frozenset({"sha256", "sha1", "md5", "ipv4", "domain", "hostname", "url"})


def _render_hypothesis_quality(hyp: HypothesisResult) -> str:
    """Render hypothesis quality rubric and falsification criteria when available."""
    has_rubric = bool(hyp.rubric_score)
    has_baselines = bool(
        hyp.expected_malicious or hyp.expected_benign or hyp.falsification_criteria
    )
    if not has_rubric and not has_baselines:
        return ""

    lines = ["", "### Hypothesis Quality & Falsification", ""]
    if has_rubric:
        score = hyp.rubric_score
        verdict = score.get("verdict", "N/A")
        total = score.get("total", 0)
        lines += [
            f"- **Rubric Gate Verdict:** `{verdict}` ({total}/15 points)",
            f"  - Specificity: {score.get('specificity', 0)}/3 | Testability: {score.get('testability', 0)}/3 | "
            f"Falsifiability: {score.get('falsifiability', 0)}/3 | Relevance: {score.get('relevance', 0)}/3 | "
            f"Pyramid Level: {score.get('pyramid_level', 0)}/3",
            "",
        ]
    if has_baselines:
        lines += [
            "| **Dimension** | **Criteria** |",
            "|---|---|",
            f"| **Expected Malicious** | {_cell(hyp.expected_malicious or '[Review CTI and populate]', 200)} |",
            f"| **Expected Benign Baseline** | {_cell(hyp.expected_benign or '[Review baseline telemetry]', 200)} |",
            f"| **Falsification Criteria** | {_cell(hyp.falsification_criteria or '[Review telemetry falsification criteria]', 200)} |",
            "",
        ]
    return "\n".join(lines)


def _render_atomic_tests(techniques: list[str], platforms: list[str] | None = None) -> str:
    """Render Atomic Red Team validation procedures for mapped techniques."""
    if not techniques:
        return ""
    try:
        from hecate_agent.core.atomic_red_team import format_atomic_tests_markdown

        content = format_atomic_tests_markdown(techniques, platforms=platforms)
        return ("\n" + content) if content else ""
    except ImportError:
        return ""


def _render_bas_verification(req: DraftHuntRequest) -> str:
    """Render closed-loop adversary emulation & breach simulation (BAS) validation findings."""
    if not req.bas_verification:
        return ""
    bas = req.bas_verification
    status = bas.get("status", "unknown")
    status_badge = {
        "verified_true_positive": "✅ **VERIFIED TRUE POSITIVE**",
        "detection_miss": "⚠️ **DETECTION MISS (Telemetry arrived, rule missed)**",
        "telemetry_missing": "❌ **TELEMETRY MISSING (Sensor blind spot - no events observed)**",
        "detonation_failed": "⚠️ **DETONATION FAILED**",
        "error": "❌ **EXECUTION ERROR**",
    }.get(status, f"`{status}`")

    provider = str(bas.get("provider", "unknown")).upper()
    technique = bas.get("technique_id", "unspecified")
    hits = bas.get("matched_events_count", 0)
    duration = bas.get("duration_seconds", 0.0)
    notes = bas.get("notes") or []
    notes_str = "; ".join(notes) if notes else ""

    lines = [
        "",
        "### Live Adversary Emulation & Breach Simulation (BAS)",
        "",
        f"> **Closed-Loop Validation Result:** {status_badge}",
        "> ",
        f"> - **Provider:** `{provider}`",
        f"> - **Target Technique:** `{technique}` ({bas.get('ability_id', '')})",
        f"> - **Telemetry Observed:** {'Yes' if bas.get('telemetry_arrived') else 'No'}",
        f"> - **Detection Triggered:** {'Yes' if bas.get('rule_triggered') else 'No'} ({hits} hit(s))",
    ]
    if duration > 0:
        lines.append(f"> - **Duration:** {duration:.2f}s")
    if notes_str:
        lines.append(f"> - **Notes:** `{notes_str}`")
    lines.append("")
    return "\n".join(lines)


def _render_soc_triage_playbook(req: DraftHuntRequest) -> str:
    """Render SOC Responder Triage Playbook (ADS-Lite) to guide analysts when alerts fire."""
    if req.hypothesis.is_indicator_only:
        return (
            "\n### SOC Responder Triage Playbook (ADS-Lite)\n\n"
            "**Target Scope:** Indicator Sweep (IOC presence in telemetry)  \n"
            "**Strategy Abstract:** Detects presence of reported network or file indicators across enterprise telemetry.\n\n"
            "#### 1. Triage & Initial Scoping (First 3 Steps)\n"
            "1. **Indicator Match Verification:** Verify whether the observed hit is an exact match against "
            "the reported indicator list (IP, domain, URL, or hash).\n"
            "2. **Host & User Scoping:** Identify endpoints or accounts that connected to or created the indicator.\n"
            "3. **Temporal Scoping:** Determine the first and last observed timestamps of the indicator activity.\n\n"
            "#### 2. Containment & IR Escalation\n"
            "- **Blocklist Enforcement:** Add confirmed malicious domains/IPs to edge proxy and firewall perimeter blocks.\n"
            "- **Host Isolation:** Isolate endpoints with confirmed execution or bidirectional communication.\n"
            "- **Incident Escalation:** Escalate to Incident Response if multiple internal hosts query or connect to the IOCs.\n\n"
            "#### 3. Detection Robustness & Evasion Cost\n"
            "- **Observable Robustness:** IOC-centric (Pyramid of Pain: Hashes / IP Addresses / Domains). Fragile and easily changed by adversary.\n"
            "- **Event Robustness:** Sensor & perimeter logging (Proxy, DNS, Firewall, EDR network events).\n"
            "- **Adversary Evasion Cost:** Low — adversary can rapidly alter domain or IP infrastructure.\n"
        )

    techniques = ", ".join(req.hypothesis.techniques) if req.hypothesis.techniques else "Unmapped"
    behavior = req.hypothesis.behavior or req.hypothesis.hypothesis or "Target behavior"
    platforms_lower = {p.strip().lower() for p in req.platforms if p.strip()}

    # Cloud / SaaS / Identity Triage Playbook
    if any(
        p
        in (
            "iaas",
            "saas",
            "cloud",
            "aws",
            "gcp",
            "azure",
            "office365",
            "m365",
            "entra id",
            "google workspace",
            "okta",
        )
        for p in platforms_lower
    ):
        return (
            "\n### SOC Responder Triage Playbook (ADS-Lite)\n\n"
            f"**Target Technique:** `{techniques}`  \n"
            f"**Strategy Abstract:** Detects `{_cell(behavior, 120)}` in Cloud/SaaS telemetry by identifying anomalous "
            "API calls, privilege escalation, or identity token abuse contrasting with the authorized baseline.\n\n"
            "#### 1. Triage & Initial Scoping (First 3 Steps)\n"
            "1. **Identity & API Verification:** Review CloudTrail, Entra, or SaaS audit logs for the invoking "
            "principal ARN, user account, source IP address, user agent, and MFA status.\n"
            "2. **Identity & Host Scoping:** Identify whether the actor assumed additional roles (STS AssumeRole), "
            "granted OAuth permissions, or generated new API access keys within +/- 2 hours of the alert.\n"
            "3. **Telemetry Correlation:** Correlate across cloud accounts, regions, or tenants for concurrent "
            "actions originating from the same session token, IP, or credential set.\n\n"
            "#### 2. Containment & IR Escalation\n"
            "- **Immediate Isolation Threshold:** Disable compromised access keys, revoke active session tokens, "
            "and remove illicit OAuth app consents or IAM role attachments immediately.\n"
            "- **Credential Invalidation:** Force password reset, revoke active refresh tokens, and re-issue MFA credentials.\n"
            "- **Incident Escalation:** Escalate to Tier-2 / IR Incident Commander if persistence mechanisms or secondary host "
            "compromise attempts are identified.\n\n"
            "#### 3. Detection Robustness & Evasion Cost\n"
            "- **Observable Robustness:** Behavioral / TTP-centric (Pyramid of Pain: TTPs). Resistant to IP or tool rotation.\n"
            "- **Event Robustness:** Control Plane / Management Plane audit telemetry (immutable CloudTrail / Entra Audit logs).\n"
            "- **Adversary Evasion Cost:** High — adversary cannot bypass management-plane audit logging without cloud control plane compromise.\n"
        )

    # Linux & Containers Triage Playbook
    if any(p in ("linux", "containers", "kubernetes") for p in platforms_lower):
        return (
            "\n### SOC Responder Triage Playbook (ADS-Lite)\n\n"
            f"**Target Technique:** `{techniques}`  \n"
            f"**Strategy Abstract:** Detects `{_cell(behavior, 120)}` on Linux/Container hosts by identifying anomalous "
            "execution patterns contrasting with authorized system administration baselines.\n\n"
            "#### 1. Triage & Initial Scoping (First 3 Steps)\n"
            "1. **Lineage Verification:** Inspect process tree, parent shell PID, executable inode/path, and namespace context "
            "to determine whether execution originated from an authorized SSH session or deployment pipeline.\n"
            "2. **Identity & Host Scoping:** Check `/var/log/auth.log`, `auditd`, and PAM events within +/- 2 hours "
            "to assess authentication method (SSH key vs password), `sudo` elevation, or abnormal TTY allocation.\n"
            "3. **Telemetry Correlation:** Correlate network socket connections with file creations in `/tmp`, `/var/tmp`, "
            "or `/dev/shm`, and check for new cron jobs or systemd service units.\n\n"
            "#### 2. Containment & IR Escalation\n"
            "- **Immediate Isolation Threshold:** Apply container network policy or host iptables isolation if unauthorized "
            "binaries execute from world-writable paths or `/etc/shadow` / credential stores are accessed.\n"
            "- **Credential Invalidation:** Terminate active SSH/TTY sessions, rotate compromised user SSH keys and passwords.\n"
            "- **Incident Escalation:** Escalate to Tier-2 / IR Incident Commander if persistence mechanisms or secondary host "
            "compromise attempts are identified.\n\n"
            "#### 3. Detection Robustness & Evasion Cost\n"
            "- **Observable Robustness:** Behavioral / TTP-centric (Pyramid of Pain: TTPs). Resistant to simple script or binary renaming.\n"
            "- **Event Robustness:** Sensor & kernel audit telemetry (`auditd`, eBPF, EDR Linux sensor).\n"
            "- **Adversary Evasion Cost:** High — adversary must redesign execution vehicle or bypass telemetry hooks.\n"
        )

    # macOS Triage Playbook
    if any(p in ("macos", "darwin", "osx") for p in platforms_lower):
        return (
            "\n### SOC Responder Triage Playbook (ADS-Lite)\n\n"
            f"**Target Technique:** `{techniques}`  \n"
            f"**Strategy Abstract:** Detects `{_cell(behavior, 120)}` on macOS endpoints by identifying anomalous "
            "execution patterns, LaunchAgent/Daemon persistence, or Gatekeeper bypass contrasting with authorized baselines.\n\n"
            "#### 1. Triage & Initial Scoping (First 3 Steps)\n"
            "1. **Lineage Verification:** Inspect process tree, parent process path, code signatures (codesign/spctl), "
            "and execution context (Terminal, Script Editor, or background service).\n"
            "2. **Identity & Host Scoping:** Check Unified Logging / OpenBSM audit trails and system logs within +/- 2 hours "
            "for authorization prompts (osascript, sudo), user login sessions, or keychain access attempts.\n"
            "3. **Telemetry Correlation:** Correlate network connections with file creations in `~/Library/LaunchAgents`, "
            "`/Library/LaunchDaemons`, `/tmp`, or `~/Library/Caches`, and check for `xattr` modifications.\n\n"
            "#### 2. Containment & IR Escalation\n"
            "- **Immediate Isolation Threshold:** Host network isolation is recommended if unsigned or ad-hoc signed Mach-O binaries execute "
            "from non-standard paths, or credential stores (Keychains, browser profiles) are accessed.\n"
            "- **Credential Invalidation:** Revoke active user sessions and rotate credentials for affected accounts.\n"
            "- **Incident Escalation:** Escalate to Tier-2 / IR Incident Commander if persistence mechanisms or secondary host "
            "compromise attempts are identified.\n\n"
            "#### 3. Detection Robustness & Evasion Cost\n"
            "- **Observable Robustness:** Behavioral / TTP-centric (Pyramid of Pain: TTPs). Resistant to file hash or binary path changes.\n"
            "- **Event Robustness:** Endpoint Security Framework (ESF) / Unified Logging sensor telemetry.\n"
            "- **Adversary Evasion Cost:** High — adversary must redesign execution vehicle or bypass macOS transparency and security hooks.\n"
        )

    # Windows & Generic Endpoint Triage Playbook
    return (
        "\n### SOC Responder Triage Playbook (ADS-Lite)\n\n"
        f"**Target Technique:** `{techniques}`  \n"
        f"**Strategy Abstract:** Detects `{_cell(behavior, 120)}` by identifying anomalous execution patterns "
        "and telemetry signatures contrasting with the established benign baseline.\n\n"
        "#### 1. Triage & Initial Scoping (First 3 Steps)\n"
        "1. **Lineage Verification:** Inspect process tree, command-line arguments, and parent-child relationships "
        "to confirm if the execution originated from an authorized administrative workflow or interactive session.\n"
        "2. **Identity & Host Scoping:** Identify the executing user principal and assess authentication logs "
        "(e.g., Event ID 4624 / IdP audit) within +/- 2 hours of alert trigger for anomalous source IPs or MFA fatigue.\n"
        "3. **Telemetry Correlation:** Correlate with network connection logs (Sysmon Event ID 3 / proxy logs) and file "
        "creations in `%TEMP%` or `%APPDATA%` to identify staging or C2 communication.\n\n"
        "#### 2. Containment & IR Escalation\n"
        "- **Immediate Isolation Threshold:** Host network isolation is recommended if unrecognized binaries execute "
        "from non-standard paths or direct credential access (e.g. LSASS access, SAM hive export) is observed.\n"
        "- **Credential Invalidation:** Revoke active user sessions and rotate credentials for affected accounts.\n"
        "- **Incident Escalation:** Escalate to Tier-2 / IR Incident Commander if persistence mechanisms or secondary host "
        "compromise attempts are identified.\n\n"
        "#### 3. Detection Robustness & Evasion Cost\n"
        "- **Observable Robustness:** Behavioral / TTP-centric (Pyramid of Pain: TTPs). Resistant to simple file hash or IP changes.\n"
        "- **Event Robustness:** Kernel / EDR sensor-level telemetry (e.g., Sysmon / EDR process creation & memory access).\n"
        "- **Adversary Evasion Cost:** High — adversary must redesign execution vehicle or bypass telemetry hooks.\n"
    )


def render_draft(req: DraftHuntRequest) -> str:
    """Return the full markdown content for a draft hunt."""
    hyp = req.hypothesis
    # Frontmatter carries only real, validated values; an unmapped field is
    # left empty rather than filled with a stand-in. "TXXXX" and
    # "unclassified" used to sit here as "honest placeholders", but both are
    # checked by `hecate-agent hunt validate` against the ATT&CK matrix, so every
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
        f"title: {_title_scalar(hyp.hypothesis)}\n"
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
        + (
            f"purple_team_validated: {str(req.purple_team_rules_validated > 0).lower()}\n"
            f"purple_team_rules_evaluated: {req.purple_team_rules_evaluated}\n"
            f"purple_team_rules_validated: {req.purple_team_rules_validated}\n"
            f"purple_team_rules_tuned: {req.purple_team_rules_tuned}\n"
            f"purple_team_telemetry_events: {req.purple_team_telemetry_count}\n"
            if req.purple_team_rules_evaluated > 0
            else ""
        )
        + (
            f"bas_verified: {str(req.bas_verification.get('status') == 'verified_true_positive').lower()}\n"
            f"bas_provider: {json.dumps(req.bas_verification.get('provider', ''))}\n"
            f"bas_status: {json.dumps(req.bas_verification.get('status', ''))}\n"
            f"bas_detection_triggered: {str(bool(req.bas_verification.get('rule_triggered'))).lower()}\n"
            if req.bas_verification
            else ""
        )
        + "---\n\n"
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

    # OBSERVE mirrors the three subsections of Hecate's own HUNT_LOCK template.
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

> {embedded_cti(req.threat_intel)}

{_render_source_evidence(req)}### Justification

{hyp.justification or "[No justification generated]"}

### ABLE Scoping

| **Field**   | **Your Input** |
|-------------|----------------|
| **Actor** | {_able_cell(hyp.actor)} |
| **Behavior** | {_able_cell(hyp.behavior)} |
| **Location** | {_able_cell(hyp.location)} |
| **Evidence** | {_able_cell(hyp.evidence)} |
{_render_hypothesis_quality(hyp)}
### Threat Intel & Research

- **MITRE ATT&CK Techniques:** {techniques_display}
- **CTI Sources & References:** {f"[{req.source_url}]({req.source_url})" if req.source_url else "[Review CTI and populate]"}
{_research_document_line(req)}
{_render_technique_evidence(req)}
{_render_claim_evidence(req)}
### Grounding

{req.grounding_section or "Not yet audited."}{_render_claim_audit(req)}

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

{_render_detection_guidance(req)}### Hunting Queries

{_render_sigma_section(req)}{_render_review_gaps(req)}
{_render_atomic_tests(techniques, platforms=req.platforms)}
{_render_bas_verification(req)}
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
{_render_soc_triage_playbook(req)}
---

**Draft Created:** {req.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")} by hecate-runner
**Next Review:** [Human review required before status can advance to `in-progress`]
"""
    return frontmatter + body


def write_draft(req: DraftHuntRequest, hunts_root: Path) -> Path:
    """Render and write the draft. Returns the file path."""
    path = draft_hunt_path(hunts_root, req.hunt_id, req.generated_at)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(path, render_draft(req))
    log.info("Wrote draft hunt %s (%d bytes)", path, path.stat().st_size)
    return path


def utcnow() -> datetime:
    return datetime.now(UTC)
