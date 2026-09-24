"""Main orchestrator loop.

One run == one cycle: pick up CTI, call hecate, write a draft. Composable so
tests can drive it with fakes and so a future long-running loop could reuse
the same ``run_once`` primitive.
"""

from __future__ import annotations

import functools
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.cti import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider, get_provider
from hecate_runner.context_metrics import measure_tokens
from hecate_runner.cti_triage import triage
from hecate_runner.grounding import TechniqueFact, audit_draft, render_grounding_section
from hecate_runner.hecate_client import HecateClient, HecateError
from hecate_runner.hunt_writer import (
    DraftHuntRequest,
    hunt_id_lock,
    next_hunt_id,
    render_draft,
    write_draft,
)
from hecate_runner.indicator_sweep import build_indicator_sweep, parse_indicator_inventory
from hecate_runner.notifications import notify_draft_created
from hecate_runner.parked_store import park, prune_parked
from hecate_runner.state import OrchestratorState

log = logging.getLogger(__name__)

# MITRE technique IDs embedded in raw CTI text, e.g. "T1003.001" or "T1053.005".
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# `hecate-agent research new --topic` expects a short label, not a raw CTI paragraph.
_TOPIC_MAX_LEN = 100

# A technique whose ATT&CK platform list is this broad (of the ~10 platforms
# ATT&CK currently defines) doesn't meaningfully scope a hunt -- e.g. T1078
# "Valid Accounts" and T1098 "Account Manipulation" both list all 10. Left
# in the union unconditionally, one such technique in a hypothesis's
# technique list (alongside genuinely narrow ones, e.g. a Windows-only
# technique) was enough to make `platform` list every ATT&CK platform verbatim
# regardless of what the CTI actually described -- 37% of one drafting batch.
# See `_resolve_ttps`.
_NON_SCOPING_PLATFORM_THRESHOLD = 8

#: The indicator-sweep hypothesis template is "Indicators published in
#: [source] appear in [telemetry] on [target]". A model that leaves [source]
#: empty yields "published in  appear" -- which reaches the draft twice, as
#: the frontmatter title and as the Hypothesis Statement, and reads like a
#: truncation bug rather than a missing value. The CTI item's own title is
#: exactly the value that belongs in that slot, so fill it here rather than
#: hoping the model stops omitting it.
#: Platform names ATT&CK uses, keyed by how a hypothesis is likely to spell
#: them. Used to scope a draft's platform list by what the hypothesis actually
#: claims: a union across every technique the CTI asserted returned
#: ESXi/Linux/macOS/Network Devices/Windows for a hypothesis whose own text
#: said "compromised Windows systems" and whose ABLE Location said "Windows
#: domain-joined endpoints".
_PLATFORM_MENTIONS: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "mac os": "macOS",
    "esxi": "ESXi",
    "network device": "Network Devices",
    "container": "Containers",
    "kubernetes": "Containers",
    "azure": "Azure AD",
    "office 365": "Office 365",
    "saas": "SaaS",
    "iaas": "IaaS",
}

#: Telemetry a technique implies, by ID prefix so sub-techniques inherit. Uses
#: the same four category names the research document and hypothesis agent
#: already speak, so a derived source and a model-proposed one are comparable.
_TECHNIQUE_DATA_SOURCES: dict[str, tuple[str, ...]] = {
    "T1059": ("process_execution",),
    "T1106": ("process_execution",),
    "T1204": ("process_execution",),
    "T1140": ("process_execution",),
    "T1620": ("process_execution",),
    "T1027": ("process_execution", "file_operations"),
    "T1005": ("file_operations", "process_execution"),
    "T1083": ("file_operations", "process_execution"),
    "T1070": ("file_operations",),
    "T1574": ("file_operations",),
    "T1105": ("network_connections", "file_operations"),
    "T1041": ("network_connections",),
    "T1071": ("network_connections",),
    "T1090": ("network_connections",),
    "T1547": ("registry_events",),
    "T1543": ("registry_events", "process_execution"),
    "T1112": ("registry_events",),
}

#: Indicator type -> telemetry that could match it. Covers both providers'
#: spellings (MISP's "ip-dst", OTX's "IPv4"); lookups lowercase the type.
_INDICATOR_DATA_SOURCES: dict[str, tuple[str, ...]] = {
    "ip-dst": ("network_connections",),
    "ip-src": ("network_connections",),
    "ipv4": ("network_connections",),
    "ipv6": ("network_connections",),
    "domain": ("network_connections",),
    "hostname": ("network_connections",),
    "url": ("network_connections",),
    "uri": ("network_connections",),
    "filename": ("file_operations", "process_execution"),
    "filepath": ("file_operations",),
    "md5": ("file_operations",),
    "sha1": ("file_operations",),
    "sha256": ("file_operations",),
    "filehash-md5": ("file_operations",),
    "filehash-sha1": ("file_operations",),
    "filehash-sha256": ("file_operations",),
    "regkey": ("registry_events",),
    "mutex": ("process_execution",),
}


def merge_techniques(cti_techniques: list[str], hypothesis_techniques: list[str]) -> list[str]:
    """Combine what the CTI asserted with what the hypothesis reasoned about.

    The hypothesis agent returns the two or three techniques it wrote prose
    around, and generalises sub-techniques while doing it -- a source event
    naming T1059.003 (Windows Command Shell) reached the draft as bare T1059.
    That is a real loss: T1059.003 is Windows-only, T1059 spans five
    platforms, so the imprecision propagates straight into the platform list.

    The CTI's list leads because it is the asserted evidence; the
    hypothesis's own additions follow. A bare parent is dropped when a
    sub-technique of it is present, so T1059 + T1059.003 collapses to the
    specific one rather than carrying both.
    """
    merged: list[str] = []
    for technique in [*cti_techniques, *hypothesis_techniques]:
        normalised = str(technique).upper().strip()
        if normalised and normalised not in merged:
            merged.append(normalised)

    parents_with_children = {t.split(".", 1)[0] for t in merged if "." in t}
    return [t for t in merged if "." in t or t not in parents_with_children]


def platforms_named_in(*texts: str) -> list[str]:
    """Platforms a hypothesis explicitly claims, in ATT&CK's spelling."""
    haystack = " ".join(t for t in texts if t).lower()
    named: list[str] = []
    for mention, platform in _PLATFORM_MENTIONS.items():
        pattern = r"\b" + re.escape(mention) + r"\b"
        if re.search(pattern, haystack) and platform not in named:
            named.append(platform)
    return named


def derive_data_sources(techniques: list[str], indicator_types: list[str]) -> list[str]:
    """Telemetry this hunt needs, from its techniques and indicator types.

    Deterministic, and independent of both the model's vocabulary and the
    environment profile. The hypothesis agent's own list is kept and merged
    with this -- it was reaching the draft as `["process_execution"]` alone
    for a hunt whose CTI carried two C2 hostnames, four IPs and nine URLs.
    """
    found: list[str] = []
    for technique in techniques or []:
        normalised = str(technique).upper().strip()
        for prefix, sources in _TECHNIQUE_DATA_SOURCES.items():
            if normalised.startswith(prefix):
                found.extend(s for s in sources if s not in found)
    for indicator_type in indicator_types or []:
        for source in _INDICATOR_DATA_SOURCES.get(str(indicator_type).lower().strip(), ()):
            if source not in found:
                found.append(source)
    return found


#: Telemetry that only exists on a given platform. The hypothesis agent
#: proposes its own data_sources list and nothing checked it against the
#: platform the techniques actually resolved to, so a macOS hunt shipped asking
#: for `registry_events` -- telemetry macOS does not have. A reviewer scoping
#: that hunt has to notice and discard it, and an automated consumer cannot.
_PLATFORM_ONLY_DATA_SOURCES: dict[str, frozenset[str]] = {
    "registry_events": frozenset({"windows"}),
}


#: Telemetry category names the model returns as if they were observations.
#: A draft came back with "What Suspicious Looks Like" reading "Process
#: execution / Network connections / File operations" -- the data source list
#: retitled, which tells a reviewer nothing about what to look for and reads
#: as if the section had been filled in.
_DATA_SOURCE_RESTATEMENTS = frozenset(
    {
        "process execution",
        "process executions",
        "process creation",
        "file operations",
        "file operation",
        "file events",
        "network connections",
        "network connection",
        "network traffic",
        "registry events",
        "registry event",
        "dns queries",
        "dns query",
        "authentication events",
    }
)


def substantive_observables(observables: list[str]) -> list[str]:
    """Drop "observables" that only restate the telemetry category.

    Kept deliberately narrow: an entry is dropped only when the whole string is
    a bare category name. "Process execution of an unsigned binary from
    /tmp" describes something a hunter can look for and stays.
    """
    kept: list[str] = []
    for observable in observables:
        text = str(observable).strip()
        normalised = text.lower().rstrip(".").replace("_", " ")
        if normalised in _DATA_SOURCE_RESTATEMENTS:
            continue
        if text:
            kept.append(text)
    return kept


def platform_consistent_data_sources(data_sources: list[str], platforms: list[str]) -> list[str]:
    """Drop telemetry that cannot exist on any of this hunt's platforms.

    Only drops when the platform list is non-empty and unambiguous about it.
    An empty platform list means scope is unknown, not that everything is
    excluded, so nothing is removed there -- the draft is a starting point for
    a human, and silently narrowing telemetry on no evidence is worse than
    leaving a source a reviewer can strike out.
    """
    if not platforms:
        return data_sources
    known = {str(p).strip().lower() for p in platforms if str(p).strip()}
    if not known:
        return data_sources

    kept: list[str] = []
    for source in data_sources:
        required = _PLATFORM_ONLY_DATA_SOURCES.get(str(source).strip().lower())
        if required is not None and not (known & required):
            continue
        kept.append(source)
    return kept


_EMPTY_SOURCE_SLOT = re.compile(r"(published in)\s{2,}(appear)", re.IGNORECASE)


def _fill_empty_source_slot(hypothesis: str, source_title: str | None) -> str:
    """Repair an indicator-sweep hypothesis whose [source] slot came back empty."""
    if not _EMPTY_SOURCE_SLOT.search(hypothesis):
        return hypothesis
    source = (source_title or "").strip() or "the source feed"
    return _EMPTY_SOURCE_SLOT.sub(lambda m: f"{m.group(1)} {source} {m.group(2)}", hypothesis)


# ATT&CK's own STIX data uses the literal platform value "PRE" for
# Reconnaissance/Resource-Development techniques (e.g. T1598 "Phishing for
# Information") that happen before the adversary has a foothold on any
# actual system -- there's no OS/environment to name yet. Surfaced verbatim,
# a hunt file's `platform: ["PRE"]` reads as a parsing bug or an unknown
# abbreviation, not what it actually means, to a human who has to scope a
# query against it. Translated at the same point _resolve_ttps already
# builds the platform list, not hardcoded as a special case in the template.
_PLATFORM_LABELS = {"PRE": "Pre-Compromise (reconnaissance/targeting -- not endpoint/OS-specific)"}


def derive_research_topic(cti_content: str, title: str | None = None) -> tuple[str, str | None]:
    """Best-effort (topic, technique) pair from a raw CTI blob.

    No NLP here on purpose — this only has to be good enough to seed the
    research agent's web searches; the research + hypothesis steps do the
    actual analysis.

    ``title`` should be the provider's clean, single-field title (e.g.
    RSS entry title, OTX pulse name, MISP event info) when the caller has
    one. Preferred over flattening/truncating ``cti_content`` -- that blob
    is "RSS: <title>\\nSource: <feed>\\nTags: ...\\nSummary: ...\\nLink:
    ...", and truncating *that whole string* at a fixed char count landed
    mid-"Source:"/"Summary:" label whenever the title alone was long,
    producing both a garbled `topic` field and a research doc contaminated
    with docs about "Source" website features whose name got the title
    pulled from the title alone. Falls back to the old flatten+truncate
    behavior only when no clean title is available.

    Known accepted limitation: for a title from a recurring series (e.g. a
    vendor's weekly "This Week in Cybersecurity"-style digest, republished
    under a near-identical title every week), the bare title alone doesn't
    disambiguate *which* edition the CTI item actually is -- the resulting
    ``topic`` can cause the research skills' web search (see
    search_system_internals/search_adversary_tradecraft in hecate's
    web_search.py) to ground against a *different* edition of the same
    series than the one this CTI item is actually about, since none of
    ``cti_content``'s more specific/disambiguating text (a summary
    mentioning the edition's actual stories) reaches the search query --
    only this function's ``topic`` return value does. Observed case: CTI
    title "The Good, the Bad and the Ugly in Cybersecurity - Week 32
    (2026)" (real content: a Snowflake breach plea, "Mythos 5", and
    ChainDrop's npm worm) produced a research doc grounded on a different
    week's edition entirely (CISO Assistant, "khunt", "The Com" takedown).
    Left unfixed for now: the actual hunt hypothesis stayed accurate in
    every observed case regardless, because hypothesis-generator weighs
    the raw CTI text over the research doc's synthesis when they diverge
    -- only the research doc itself (not the hunt) ends up describing the
    wrong content. Revisit if a bad research grounding ever does end up
    steering a hunt wrong, not just looking wrong on its own.
    """
    technique_match = _TECHNIQUE_RE.search(cti_content)
    technique = technique_match.group(0) if technique_match else None

    topic = (title or " ".join(cti_content.split())).strip()
    if len(topic) > _TOPIC_MAX_LEN:
        truncated = topic[:_TOPIC_MAX_LEN]
        # Prefer cutting on a word boundary so we don't hand the agent a
        # half-word topic.
        if " " in truncated:
            truncated = truncated.rsplit(" ", 1)[0]
        topic = truncated
    return topic or "Untitled CTI", technique


def has_narrative(cti_content: str) -> bool:
    """Whether ``cti_content`` carries substance beyond a bare indicator dump.

    All three CTI providers build their blurb around a "does this item have
    a human-written description" branch: RSS's ``_entry_to_blurb`` appends a
    ``Summary:`` line only when the entry has one, OTX's ``_pulse_to_blurb``
    appends a ``Description:`` line only when the pulse has one, and MISP's
    ``_event_to_blurb`` has no narrative field to append at all -- a MISP
    event carries a title (``info``) and structured metadata, not prose.

    An explicit ``MITRE ATT&CK Techniques:`` line counts too, and all three
    providers emit it under that same label. It is not prose, but the
    question this gates is not "is there prose" -- it is "is there anything
    here besides an IOC dump and a title." A stated technique list is an
    analyst asserting observed behavior, which is the strongest form of that
    evidence available short of prose, and it is precisely what a bulk
    indicator dump cannot produce: ThreatFox-style events carry no galaxy
    cluster, so they reach no such line.

    Without this, every MISP event failed the check no matter how well
    curated -- classified as an indicator sweep, routed past research, and
    rendered with ``techniques: []`` even though the event had just handed
    us fifteen technique IDs. That silently cancelled out the galaxy filter
    and org allowlist, whose whole purpose is selecting ATT&CK-mapped events.

    Gates two things, both failing the same way for the same reason -- a
    bare IOC-count blurb gives each step nothing real to work from, and both
    fill the gap from background knowledge rather than leaving it empty:

    - Web search during research. Tavily has nothing of substance to match,
      so it grounds on whatever else shares the topic's generic/templated
      title -- observed fabricating malware family names ("PureRAT and
      Overlord RAT") that propagated into the hunt file, unlike the
      recurring-digest-title case in `derive_research_topic` where the hunt
      stayed accurate because the CTI still had real text to fall back on.
    - Hypothesis generation. The agent's default template obliges the model
      to name a behavior, so against a list of domains it invented one --
      "phishing emails" as the delivery vector, "stolen credentials ...
      lateral movement" as follow-on activity, plus an unsupported ATT&CK
      technique. See `HecateClient.hypothesis_generator`'s indicators_only.
    """
    return (
        "Description:" in cti_content
        or "Summary:" in cti_content
        or ATTACK_TECHNIQUE_LINE in cti_content
    )


#: How many non-actionable items one cycle may walk past before giving up.
#: A feed of nothing but vendor blog posts should cost a single cycle, not an
#: unbounded walk through the archive.
_MAX_SKIPS_PER_CYCLE = 5


#: Field prefixes the providers emit. Everything a blurb says about itself
#: rather than about the threat.
_BLURB_FIELD_PREFIXES = (
    "RSS:",
    "OTX Pulse:",
    "MISP Event:",
    "Source:",
    "Link:",
    "Tags:",
    "Org:",
    "TLP:",
    "Threat Level:",
    "Adversary/Attribution:",
    "References:",
    "Indicators (",
    "Key indicators:",
    ATTACK_TECHNIQUE_LINE,
)


def _carries_free_text(cti_content: str) -> bool:
    """Whether anything here is prose rather than a provider metadata field.

    This is what separates "the blurb had no narrative field" from "there is
    no narrative". The file queue takes free-form text a human wrote --
    "APT actor X observed dumping LSASS via comsvcs.dll" -- which carries no
    `Summary:` marker and would otherwise read as empty.
    """
    for line in cti_content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Indented lines continue the field above them (values under
        # "Key indicators:").
        if line[:1].isspace():
            continue
        if stripped.startswith(_BLURB_FIELD_PREFIXES):
            continue
        return True
    return False


def is_actionable(cti_content: str) -> bool:
    """Whether there is anything here to build a hunt from.

    Three ways to qualify, and an item needs only one: a narrative field a
    hypothesis can be grounded in, a parseable indicator inventory a sweep can
    be built from, or free-form prose that is not provider metadata.

    The third clause is load-bearing. ``has_narrative`` recognises the
    *markers* provider blurbs use, so its absence is not evidence that no
    narrative exists -- and treating it as such discarded the file queue's
    hand-written CTI outright when this gate was first written.

    What is left over is the case this exists for: a blurb that is nothing but
    its own metadata. H-0630 was four lines -- title, source, tags, link --
    off a vendor marketing post, and became "Indicators published in Teaching
    AI to Reason Through Detection Triage appear in telemetry", a sweep for
    indicators that do not exist.

    This is a floor, not a quality bar. It does not ask whether the prose is
    *about* a specific threat; a conference write-up passes. That is the
    harder half of C4 and is deliberately still open.
    """
    return (
        has_narrative(cti_content)
        or bool(parse_indicator_inventory(cti_content))
        or _carries_free_text(cti_content)
    )


@dataclass
class RunResult:
    """Structured outcome of one orchestrator cycle."""

    outcome: str
    detail: str = ""
    hunt_id: str | None = None
    draft_path: Path | None = None
    research_id: str | None = None
    parked_count: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome in {
            "draft_created",
            "no_cti",
            "no_actionable_cti",
            "quota_reached",
            "research_quota_reached",
        }


class Orchestrator:
    """Owns the wiring; one instance per run is fine."""

    def __init__(
        self,
        settings: Settings,
        hecate: HecateClient,
        cti_provider: CTIProvider,
        notify: Callable[[RunResult], None] | None = None,
    ):
        self.settings = settings
        self.hecate = hecate
        self.cti = cti_provider
        # Defaults to a no-op so tests and callers that don't care about
        # notifications don't have to pass one.
        self.notify = notify or (lambda result: None)

    # --- Public API --------------------------------------------------------

    def run_once(self, *, dry_run: bool = False) -> RunResult:
        """Execute one cycle. Never raises; always returns a RunResult."""
        log.info("=== Orchestrator cycle starting (dry_run=%s) ===", dry_run)
        state = OrchestratorState.load(self.settings.state_file)

        if self.settings.parked_max_age_days > 0:
            prune_parked(self.settings.cti_queue_dir_resolved, self.settings.parked_max_age_days)
        try:
            result = self._run_body(state, dry_run=dry_run)
            state.mark_run(success=result.ok)
            return result
        except Exception as exc:  # top-level guard
            log.exception("Cycle failed unexpectedly: %s", exc)
            state.mark_run(success=False)
            return RunResult(outcome="error", detail=str(exc))
        finally:
            state.save(self.settings.state_file)
            log.info("=== Orchestrator cycle complete ===")

    # --- Internal ----------------------------------------------------------

    def _grounding_section(
        self,
        req: DraftHuntRequest,
        item: CTIItem,
        technique_facts: dict[str, TechniqueFact] | None = None,
    ) -> str:
        """Audit the draft as it currently stands and render the result.

        Best-effort: an audit that raises must not cost a hunt that is
        otherwise complete, so a failure leaves the section empty rather than
        aborting the cycle.
        """
        # Audit the draft *without* its own previous Grounding section. The
        # section is re-rendered on the second pass (after Sigma), and feeding
        # a claim table back through the extractor would have the audit read
        # its own output as though it were hunt content.
        previous_section, req.grounding_section = req.grounding_section, ""
        try:
            draft_text = render_draft(req)
        finally:
            req.grounding_section = previous_section

        try:
            report = audit_draft(
                draft_text=draft_text,
                cti_text=item.content,
                research_text=self._research_text(req.research_id),
                cti_techniques=[str(t) for t in (item.metadata.get("techniques") or [])],
                technique_facts=technique_facts,
                hunt_platforms=list(req.platforms),
            )
        except Exception as exc:
            log.warning("Grounding audit failed for %s (%s); section left empty.", req.hunt_id, exc)
            return ""

        if report.unsupported:
            log.warning(
                "%s carries %d claim(s) that trace to no source: %s",
                req.hunt_id,
                len(report.unsupported),
                ", ".join(c.value for c in report.unsupported),
            )
        return render_grounding_section(report)

    def _research_text(self, research_id: str | None) -> str:
        """The research document's text, so its cited sources also count as
        grounding for a claim the CTI itself did not make."""
        if not research_id:
            return ""
        path = self.settings.hecate_workspace / "research" / f"{research_id}.md"
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def _attach_sigma_rules(
        self,
        req: DraftHuntRequest,
        path: Path,
        item: CTIItem,
        technique_facts: dict[str, TechniqueFact] | None = None,
    ) -> None:
        """Draft Sigma rules for the hunt and rewrite the draft to include them.

        Techniques come from the CTI itself where the provider supplied them,
        not from the hypothesis. The hypothesis narrows to the two or three
        techniques it reasoned about; the source event asserted fifteen, and
        the log sources a hunt should cover follow from all of them. Falling
        back to the hypothesis keeps providers that map no techniques working.
        """
        techniques = list(item.metadata.get("techniques") or []) or list(req.hypothesis.techniques)
        indicators = dict(item.metadata.get("indicators") or {})
        out_dir = self.settings.hecate_workspace / "queries" / req.hunt_id

        payload = {
            "hunt_id": req.hunt_id,
            "hypothesis": req.hypothesis.hypothesis,
            "justification": req.hypothesis.justification,
            "techniques": techniques,
            "platforms": req.platforms,
            "indicators": indicators,
            "references": [item.source_url] if item.source_url else [],
            # The draft's observables and ABLE evidence carry what grounded
            # research found -- H-0002's `nvidia-sysruntime.exe` -- which the
            # generator otherwise never sees, so it invented `.nvidia.exe`.
            "observables": [
                o for o in [*req.hypothesis.observables, req.hypothesis.evidence] if o and o.strip()
            ],
        }
        import json
        payload_str = json.dumps(payload)
        input_tokens = measure_tokens(payload_str, model_name=self.settings.hecate_llm_model or "gpt-4")
        log.info("Context Window Metrics: Executing sigma_generator with ~%d input tokens", input_tokens)

        try:
            result = self.hecate.sigma_generator(
                payload, out_dir, timeout_sec=self.settings.sigma_timeout_sec
            )
        except HecateError as exc:
            log.warning(
                "Sigma drafting failed for %s (%s); draft keeps its placeholder query section.",
                req.hunt_id,
                exc,
            )
            return

        # A rejected rule is not retried, so its reason is the only record of
        # why a log source came back empty. The client's `warnings` is always
        # empty; the reasons live in `rejected`.
        for reason in result.rejected:
            log.info("Sigma rule rejected for %s: %s", req.hunt_id, reason)

        if not result.success or not result.rules:
            log.warning(
                "Sigma drafting produced no usable rules for %s (%s); draft keeps its placeholder query section.",
                req.hunt_id,
                result.error or "no rules returned",
            )
            return

        for warning in result.warnings:
            log.info("Sigma drafting note for %s: %s", req.hunt_id, warning)

        req.sigma_rules = result.rules
        try:
            req.sigma_rule_dir = str(out_dir.relative_to(self.settings.hecate_workspace))
        except ValueError:  # out_dir outside the workspace -- show it whole
            req.sigma_rule_dir = str(out_dir)

        # Re-audit: the rules just added are themselves claims, and a rule
        # matching a C2 domain no source mentions is exactly what the audit
        # exists to surface.
        req.grounding_section = self._grounding_section(req, item, technique_facts)
        try:
            atomic_write_text(path, render_draft(req))
        except OSError as exc:
            log.warning(
                "Generated %d Sigma rule(s) for %s but could not rewrite the draft (%s); "
                "the rule files are still at %s.",
                len(result.rules),
                req.hunt_id,
                exc,
                out_dir,
            )
            return

        log.info(
            "Attached %d Sigma rule(s) to %s covering %s",
            len(result.rules),
            req.hunt_id,
            ", ".join(sorted({str(r.get("logsource_category")) for r in result.rules})),
        )

    def _resolve_ttps(
        self,
        techniques: list[str],
        scope_text: str = "",
        facts: dict[str, TechniqueFact] | None = None,
    ) -> tuple[list[str], list[str]]:
        """Derive real tactics/platforms for a hypothesis's techniques.

        Looks each technique up against live ATT&CK data instead of
        hardcoding a fixed tactic/platform onto every draft regardless of
        what the CTI actually described. Order-preserving de-dup across
        techniques; a technique that fails to resolve (unknown ID, STIX
        unavailable) just contributes nothing rather than raising.

        Platforms from a near-universal technique (see
        `_NON_SCOPING_PLATFORM_THRESHOLD`) are excluded from the union: they
        carry no scoping signal and, unioned in, silently swamp genuinely
        narrow techniques also present on the same hypothesis. Tactics
        aren't filtered the same way -- a technique's tactic (e.g.
        "persistence") stays meaningful and low-cardinality even when its
        platform list is broad. If every resolved technique happens to be
        broad, `platforms` comes back empty and stays empty in the draft's
        frontmatter -- an honest gap signal rather than a fabricated
        full-platform list.
        """
        tactics: list[str] = []
        platforms: list[str] = []
        for technique_id in techniques:
            meta = self.hecate.lookup_technique(
                technique_id, timeout_sec=self.settings.llm_timeout_sec
            )
            # Record what the matrix said so the grounding audit can call out
            # an invented ID without paying for these subprocess lookups twice.
            if facts is not None:
                facts[technique_id.upper()] = TechniqueFact(
                    valid=meta.found,
                    superseded_by=(meta.superseded_from and meta.technique_id) or "",
                    names=tuple(n for n in (meta.name, meta.parent_name) if n),
                    # Relabelled to the frontmatter vocabulary so the audit can
                    # compare them against the hunt's own platform list. A
                    # near-universal technique records nothing: it carries no
                    # scoping signal, so it must not be able to contradict one.
                    platforms=(
                        ()
                        if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD
                        else tuple(_PLATFORM_LABELS.get(pf, pf) for pf in meta.platforms)
                    ),
                )
            for tactic in meta.tactics:
                if tactic not in tactics:
                    tactics.append(tactic)
            if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD:
                continue
            for platform in meta.platforms:
                platform = _PLATFORM_LABELS.get(platform, platform)
                if platform not in platforms:
                    platforms.append(platform)

        # A hypothesis that names its platforms outranks the union. Unioning
        # across every technique the CTI asserted is right for "where could
        # this technique occur" and wrong for "where does this hunt look":
        # it returned five platforms for a hypothesis whose own sentence said
        # "compromised Windows systems". Only narrows -- a claimed platform
        # that no resolved technique supports is ignored rather than added,
        # and if the two share nothing the union stands.
        claimed = platforms_named_in(scope_text)
        if claimed:
            scoped = [p for p in platforms if p in claimed]
            # If the resolved techniques have ZERO overlap with what was claimed
            # (e.g. LLM suggested T1207 Windows for a macOS hunt), the technique
            # is hallucinated. The claimed text is the source of truth.
            final_platforms = scoped if scoped else claimed

            # Mark any technique that strongly contradicts our final platforms as invalid
            # so it is stripped from the payload and doesn't pollute the Sigma generator
            if facts is not None:
                for tech_id, fact in facts.items():
                    if fact.platforms and not any(p in final_platforms for p in fact.platforms):
                        fact.valid = False

            return tactics, final_platforms

        return tactics, platforms

    def _advance_past(self, item: CTIItem) -> bool:
        """Acknowledge an item so the cursor moves; False if it could not.

        Without the advance the same item is returned by the next call, so a
        caller that keeps looping would spin on it forever.
        """
        try:
            self.cti.acknowledge(item)
        except Exception as exc:  # provider-specific cursor failures
            log.warning("Could not advance past CTI item (%s); stopping this cycle.", exc)
            return False
        return True

    def _next_actionable_item(self) -> tuple[CTIItem | None, int, int]:
        """The next CTI item worth drafting, and how many were walked past, and how many parked.

        An item with neither narrative nor a parseable indicator inventory
        offers nothing to hunt. Drafted anyway it produced H-0630 --
        "Indicators published in Teaching AI to Reason Through Detection
        Triage appear in telemetry", a sweep for indicators that do not
        exist, off a vendor marketing post.

        Skipped items are acknowledged so the cursor advances past them
        instead of the same item being re-offered every cycle. This runs
        before the quota is reserved: walking past an item is not a draft and
        must not cost one.
        """
        skipped = 0
        parked_count = 0
        for _ in range(_MAX_SKIPS_PER_CYCLE + 1):
            item = self.cti.next_item()
            if item is None:
                return None, skipped, parked_count
            if is_actionable(item.content):
                verdict = triage(item) if self.settings.cti_triage == "park" else None
                if verdict is None or not verdict.park:
                    return item, skipped, parked_count
                # Held back, not dropped: the cursor has already moved past
                # this item, so the copy written here is the only one left.
                skipped += 1
                parked_count += 1
                log.info(
                    "Parking CTI item from %s (%s): %s",
                    item.source,
                    item.title[:60] or "untitled",
                    verdict.reason,
                )
                try:
                    park(self.settings.cti_queue_dir_resolved, item, verdict.reason)
                except OSError as exc:
                    # Parking is the whole safety net. If it cannot be written,
                    # draft the item rather than losing it.
                    log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                    parked_count -= 1
                    return item, skipped - 1, parked_count
                if not self._advance_past(item):
                    return None, skipped, parked_count
                continue

            # Counted where the decision is made, not after the cursor moves:
            # an item we could not advance past was still found and rejected,
            # and reporting "no CTI in queue" for it would be untrue.
            skipped += 1
            log.info(
                "Skipping CTI item from %s: no narrative, no parseable indicator "
                "inventory and no free-form prose, so there is nothing to hunt.",
                item.source,
            )
            if not self._advance_past(item):
                return None, skipped, parked_count

        log.info("Found %d non-actionable CTI items; stopping this cycle.", skipped)
        return None, skipped, parked_count

    def _run_body(self, state: OrchestratorState, *, dry_run: bool) -> RunResult:
        item, skipped, parked_count = self._next_actionable_item()
        if item is None:
            if skipped:
                log.info("No actionable CTI this cycle; %d item(s) had nothing to hunt.", skipped)
                return RunResult(
                    outcome="no_actionable_cti",
                    detail=f"skipped {skipped}",
                    parked_count=parked_count,
                )
            log.info("No CTI in queue; nothing to do this cycle.")
            return RunResult(outcome="no_cti", parked_count=parked_count)

        log.info("Picked up CTI item from %s (%d chars)", item.source, len(item.content))

        if not state.check_and_reserve_draft(self.settings.max_drafts_per_day):
            log.warning(
                "Daily draft quota reached (%d). Leaving CTI in queue for next cycle.",
                self.settings.max_drafts_per_day,
            )
            return RunResult(
                outcome="quota_reached",
                detail=f"{state.drafts_today}/{self.settings.max_drafts_per_day}",
            )

        if dry_run:
            log.info("[dry-run] Would call hecate and write a draft; leaving CTI in queue.")
            state.drafts_today -= 1  # reverse the reservation in dry-run
            state.total_drafts_ever -= 1
            return RunResult(
                outcome="dry_run", detail=item.content[:100], parked_count=parked_count
            )

        # Computed once for the whole cycle: the same "is there any prose
        # here?" answer gates web search during research (nothing real to
        # search for) and constrains hypothesis generation afterwards
        # (nothing real to infer a behavior from).
        intel_has_narrative = has_narrative(item.content)
        if not intel_has_narrative:
            log.info(
                "CTI item has no narrative (bare IOC dump); disabling web search and "
                "constraining the hypothesis to indicator presence for this cycle."
            )

        # A narrative-free dump whose indicator inventory we can actually read
        # gets a deterministic sweep draft below -- no LLM call, so no slot for
        # the model to invent a delivery vector or technique into.
        #
        # Both halves of that condition matter. `has_narrative` is a
        # heuristic over provider blurb formats, and if it were wrong on its
        # own, building the draft from a template would *discard* real
        # narrative CTI -- a worse failure than the fabrication this fixes.
        # Requiring a parseable inventory as well means we act only on
        # positive evidence that this really is a feed dump; anything else
        # falls through to the LLM with the indicators-only constraint,
        # which degrades safely either way.
        #
        # Computed here, ahead of research, because it now also decides
        # whether research runs at all.
        sweep_inventory = {} if intel_has_narrative else parse_indicator_inventory(item.content)

        research_id: str | None = None
        related_hunts: list[str] = []
        if sweep_inventory:
            # `hecate-agent research new` on a bare indicator dump spends four skills
            # producing "insufficient information" boilerplate -- measured
            # across R-0604/R-0608/R-0610 at ~2 minutes and 4 LLM calls each
            # for a document with no findings, no telemetry mapping and no
            # techniques, which the draft then linked as "detailed pre-hunt
            # research". The sweep draft below is built from the indicator
            # inventory alone, so there is nothing for that call to ground.
            #
            # This keys off sweep_inventory rather than intel_has_narrative on
            # purpose: a narrative-free dump we could NOT parse still falls
            # through to the LLM hypothesis generator, and that path must stay
            # grounded (ungrounded generation measured ~30% accuracy).
            log.info("CTI is a parseable indicator dump; skipping research grounding.")
        elif self.settings.research_enabled:
            # Only a narrative search spends Tavily credits, so only that
            # counts. Refused rather than drafted ungrounded, for the same
            # reason a research failure is: the CTI waits for tomorrow's quota.
            if intel_has_narrative and not state.check_and_reserve_research(
                self.settings.max_research_runs_per_day
            ):
                log.warning(
                    "Daily research quota reached (%d). Leaving CTI in queue for next cycle.",
                    self.settings.max_research_runs_per_day,
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(
                    outcome="research_quota_reached",
                    detail=f"{state.research_runs_today}/{self.settings.max_research_runs_per_day}",
                    parked_count=parked_count,
                )
            topic, technique = derive_research_topic(item.content, title=item.title or None)
            
            # Measure context usage for optimization
            input_tokens = measure_tokens(topic, model_name=self.settings.hecate_llm_model or "gpt-4")
            log.info("Context Window Metrics: Executing research_new with ~%d input tokens", input_tokens)

            try:
                research_result = self.hecate.research_new(
                    topic=topic,
                    technique=technique,
                    depth=self.settings.research_depth,
                    timeout_sec=self.settings.llm_timeout_sec,
                    web_search_enabled=intel_has_narrative,
                )
            except HecateError as exc:
                # Cold (ungrounded) generation measured ~30% accuracy on known-
                # answer fixtures (see `hecate-agent eval`) — a research failure is
                # refused rather than silently falling back to that. Refund
                # the quota; the CTI stays in the queue for the next cycle.
                log.error(
                    "hecate-agent research new failed (%s); refusing to generate an ungrounded hypothesis",
                    exc,
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(
                    outcome="research_error", detail=str(exc), parked_count=parked_count
                )

            if research_result.is_empty:
                log.error(
                    "hecate-agent research new produced no research_id; refusing to generate an ungrounded hypothesis"
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="research_empty", parked_count=parked_count)

            research_id = research_result.research_id
            related_hunts = research_result.related_hunts
            log.info("Research %s grounds this cycle's hypothesis", research_id)

        if sweep_inventory:
            log.info(
                "CTI is an indicator dump (%d indicators, %d type(s)); building a sweep "
                "draft directly instead of generating a behavioral hypothesis.",
                sum(sweep_inventory.values()),
                len(sweep_inventory),
            )
            hypothesis = build_indicator_sweep(item.content, title=item.title or None)
        else:
            # Measure context usage for optimization
            input_tokens = measure_tokens(item.content, model_name=self.settings.hecate_llm_model or "gpt-4")
            log.info("Context Window Metrics: Executing hypothesis_generator with ~%d input tokens", input_tokens)
            try:
                hypothesis = self.hecate.hypothesis_generator(
                    threat_intel=item.content,
                    research_id=research_id,
                    timeout_sec=self.settings.llm_timeout_sec,
                    indicators_only=not intel_has_narrative,
                )
            except HecateError as exc:
                log.error("hecate hypothesis-generator failed: %s", exc)
                # Refund the quota — the CTI stays in the queue.
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="hecate_error", detail=str(exc), parked_count=parked_count)

        repaired = _fill_empty_source_slot(hypothesis.hypothesis, item.title)
        if repaired != hypothesis.hypothesis:
            log.info("Filled empty [source] slot in indicator-sweep hypothesis from CTI title.")
            hypothesis.hypothesis = repaired

        if hypothesis.is_empty:
            log.warning("hecate returned empty hypothesis; refunding quota and leaving CTI.")
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="empty_hypothesis", parked_count=parked_count)

        # Restore what the pipeline was discarding before the draft is built.
        # The hypothesis agent returns only the techniques it reasoned about,
        # generalised (T1059.003 -> T1059); the CTI asserted the full, precise
        # list. Merging is what keeps the draft's ATT&CK mapping, its platform
        # scope and its telemetry list faithful to the source.
        cti_techniques = [str(t) for t in (item.metadata.get("techniques") or [])]
        hypothesis.techniques = merge_techniques(cti_techniques, hypothesis.techniques)

        indicator_types = list((item.metadata.get("indicators") or {}).keys())
        for source in derive_data_sources(hypothesis.techniques, indicator_types):
            if source not in hypothesis.data_sources:
                hypothesis.data_sources.append(source)

        technique_facts: dict[str, TechniqueFact] = {}
        tactics, platforms = self._resolve_ttps(
            hypothesis.techniques,
            scope_text=" ".join([hypothesis.hypothesis, hypothesis.location]),
            facts=technique_facts,
        )

        # Applied here rather than at merge time: the platform list only
        # exists once the techniques have resolved against the live matrix.
        hypothesis.data_sources = platform_consistent_data_sources(
            hypothesis.data_sources, platforms
        )

        # An empty section is honest; a section listing the telemetry
        # categories back is not, and a reviewer skims past it as done.
        kept_observables = substantive_observables(hypothesis.observables)
        if kept_observables != hypothesis.observables:
            log.info(
                "Dropped %d observable(s) that only restated a telemetry category",
                len(hypothesis.observables) - len(kept_observables),
            )
        hypothesis.observables = kept_observables or ["[none proposed - human to populate]"]

        # 4.2 Drop unresolvable technique IDs from the draft so they don't
        # reach the frontmatter and break `hunt validate` downstream.
        hypothesis.techniques = [
            t
            for t in hypothesis.techniques
            if t.upper() not in technique_facts or technique_facts[t.upper()].valid
        ]

        try:
            with hunt_id_lock(self.settings.hunts_root):
                hunt_id = next_hunt_id(self.settings.hunts_root)
                req = DraftHuntRequest(
                    hunt_id=hunt_id,
                    threat_intel=item.content,
                    hypothesis=hypothesis,
                    generated_at=datetime.now(UTC),
                    research_id=research_id,
                    tactics=tactics,
                    platforms=platforms,
                    source_url=item.source_url,
                    related_hunts=related_hunts,
                )
                req.grounding_section = self._grounding_section(req, item, technique_facts)
                path = write_draft(req, self.settings.hunts_root)
        except OSError as exc:
            log.error("Failed to allocate/write draft hunt file: %s", exc)
            # Refund the quota — nothing was actually drafted, and the CTI
            # item is still unacknowledged so it stays queued for retry.
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="write_error", detail=str(exc), parked_count=parked_count)

        # Close the loop back to the research document. Isolated like the
        # other post-write steps: the draft already exists and its quota is
        # already spent, so a link failure is a warning, not a lost hunt.
        if research_id:
            try:
                self.hecate.link_research_to_hunt(
                    research_id, hunt_id, timeout_sec=self.settings.llm_timeout_sec
                )
            except HecateError as exc:
                log.warning(
                    "Could not link %s back to %s (%s); the hunt still records "
                    "spawned_from, so the forward reference is intact.",
                    hunt_id,
                    research_id,
                    exc,
                )

        # The draft file already exists on disk at this point. Acknowledge the
        # CTI item and save state *before* the multi-minute Sigma drafting
        # step, so if the process is killed during Sigma generation, we don't
        # lose the quota count and re-draft the exact same CTI item next cycle.
        try:
            self.cti.acknowledge(item)
            state.save(self.settings.state_file)
        except Exception as exc:  # isolate from the top-level guard
            log.warning(
                "Failed to acknowledge CTI item or save state after successfully drafting %s (%s); "
                "this item may be re-drafted under a new ID next cycle.",
                hunt_id,
                exc,
            )

        # Sigma drafting sits here deliberately: after the file exists, and
        # outside hunt_id_lock. It is a multi-minute LLM call, and holding
        # the ID-allocation lock across it would stall every concurrent
        # cycle behind it. The draft is rewritten in place once rules are
        # in hand, so a failure leaves the hunt standing with its
        # placeholder query section rather than losing it.
        if self.settings.sigma_generation_enabled:
            self._attach_sigma_rules(req, path, item, technique_facts)

        log.info(
            "Draft %s created at %s (research=%s, drafts today: %d/%d)",
            hunt_id,
            path,
            research_id or "none",
            state.drafts_today,
            self.settings.max_drafts_per_day,
        )

        result = RunResult(
            outcome="draft_created",
            hunt_id=hunt_id,
            draft_path=path,
            research_id=research_id,
        )

        # A notification failure must not turn an already-successful draft
        # into an "error" outcome — isolate it from the run_once() top-level
        # exception guard rather than letting it propagate.
        try:
            self.notify(result)
        except Exception as exc:  # notifications are best-effort, never fatal
            log.warning(
                "Draft-created notification failed (%s); draft %s was still created", exc, hunt_id
            )

        return result


# --- Factory ---------------------------------------------------------------


def build_default_orchestrator(settings: Settings) -> Orchestrator:
    """Wire up the standard orchestrator from settings alone."""
    hecate = HecateClient(
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
        env_overrides=settings.env_for_hecate(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    cti = get_provider(settings.cti_provider, settings=settings)
    notify = functools.partial(notify_draft_created, settings)
    return Orchestrator(settings=settings, hecate=hecate, cti_provider=cti, notify=notify)
