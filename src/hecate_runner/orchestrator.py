"""Main orchestrator loop.

One run == one cycle: pick up CTI, call athf, write a draft. Composable so
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

from hecate_runner.athf_client import AthfClient, AthfError
from hecate_runner.config import Settings
from hecate_runner.cti import ATTACK_TECHNIQUE_LINE, CTIProvider, get_provider
from hecate_runner.hunt_writer import DraftHuntRequest, hunt_id_lock, next_hunt_id, write_draft
from hecate_runner.indicator_sweep import build_indicator_sweep, parse_indicator_inventory
from hecate_runner.notifications import notify_draft_created
from hecate_runner.state import OrchestratorState

log = logging.getLogger(__name__)

# MITRE technique IDs embedded in raw CTI text, e.g. "T1003.001" or "T1053.005".
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# `athf research new --topic` expects a short label, not a raw CTI paragraph.
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
    search_system_internals/search_adversary_tradecraft in athf's
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
      technique. See `AthfClient.hypothesis_generator`'s indicators_only.
    """
    return (
        "Description:" in cti_content
        or "Summary:" in cti_content
        or ATTACK_TECHNIQUE_LINE in cti_content
    )


@dataclass
class RunResult:
    """Structured outcome of one orchestrator cycle."""

    outcome: str
    detail: str = ""
    hunt_id: str | None = None
    draft_path: Path | None = None
    research_id: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome in {"draft_created", "no_cti", "quota_reached"}


class Orchestrator:
    """Owns the wiring; one instance per run is fine."""

    def __init__(
        self,
        settings: Settings,
        athf: AthfClient,
        cti_provider: CTIProvider,
        notify: Callable[[RunResult], None] | None = None,
    ):
        self.settings = settings
        self.athf = athf
        self.cti = cti_provider
        # Defaults to a no-op so tests and callers that don't care about
        # notifications don't have to pass one.
        self.notify = notify or (lambda result: None)

    # --- Public API --------------------------------------------------------

    def run_once(self, *, dry_run: bool = False) -> RunResult:
        """Execute one cycle. Never raises; always returns a RunResult."""
        log.info("=== Orchestrator cycle starting (dry_run=%s) ===", dry_run)
        state = OrchestratorState.load(self.settings.state_file)
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

    def _resolve_ttps(self, techniques: list[str]) -> tuple[list[str], list[str]]:
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
            meta = self.athf.lookup_technique(
                technique_id, timeout_sec=self.settings.llm_timeout_sec
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
        return tactics, platforms

    def _run_body(self, state: OrchestratorState, *, dry_run: bool) -> RunResult:
        item = self.cti.next_item()
        if item is None:
            log.info("No CTI in queue; nothing to do this cycle.")
            return RunResult(outcome="no_cti")

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
            log.info("[dry-run] Would call athf and write a draft; leaving CTI in queue.")
            state.drafts_today -= 1  # reverse the reservation in dry-run
            state.total_drafts_ever -= 1
            return RunResult(outcome="dry_run", detail=item.content[:100])

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
            # `athf research new` on a bare indicator dump spends four skills
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
            topic, technique = derive_research_topic(item.content, title=item.title or None)
            try:
                research_result = self.athf.research_new(
                    topic=topic,
                    technique=technique,
                    depth=self.settings.research_depth,
                    timeout_sec=self.settings.llm_timeout_sec,
                    web_search_enabled=intel_has_narrative,
                )
            except AthfError as exc:
                # Cold (ungrounded) generation measured ~30% accuracy on known-
                # answer fixtures (see `athf eval`) — a research failure is
                # refused rather than silently falling back to that. Refund
                # the quota; the CTI stays in the queue for the next cycle.
                log.error(
                    "athf research new failed (%s); refusing to generate an ungrounded hypothesis",
                    exc,
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="research_error", detail=str(exc))

            if research_result.is_empty:
                log.error(
                    "athf research new produced no research_id; refusing to generate an ungrounded hypothesis"
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="research_empty")

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
            try:
                hypothesis = self.athf.hypothesis_generator(
                    threat_intel=item.content,
                    research_id=research_id,
                    timeout_sec=self.settings.llm_timeout_sec,
                    indicators_only=not intel_has_narrative,
                )
            except AthfError as exc:
                log.error("athf hypothesis-generator failed: %s", exc)
                # Refund the quota — the CTI stays in the queue.
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="athf_error", detail=str(exc))

        repaired = _fill_empty_source_slot(hypothesis.hypothesis, item.title)
        if repaired != hypothesis.hypothesis:
            log.info("Filled empty [source] slot in indicator-sweep hypothesis from CTI title.")
            hypothesis.hypothesis = repaired

        if hypothesis.is_empty:
            log.warning("athf returned empty hypothesis; refunding quota and leaving CTI.")
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="empty_hypothesis")

        tactics, platforms = self._resolve_ttps(hypothesis.techniques)

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
                path = write_draft(req, self.settings.hunts_root)
        except OSError as exc:
            log.error("Failed to allocate/write draft hunt file: %s", exc)
            # Refund the quota — nothing was actually drafted, and the CTI
            # item is still unacknowledged so it stays queued for retry.
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="write_error", detail=str(exc))

        # The draft file already exists on disk at this point. A failure from
        # here on must NOT be treated as "the cycle failed" (that would
        # incorrectly mark state.mark_run(success=False) despite real forward
        # progress having happened) or refund the quota (a real draft WAS
        # produced — that's legitimate usage). acknowledge() failing just
        # means the CTI item's cursor didn't advance, so it may be picked up
        # and redrafted under a new ID next cycle — worth a loud warning, not
        # a cycle-level failure that also risks silently duplicating content.
        try:
            self.cti.acknowledge(item)
        except Exception as exc:  # isolate from the top-level guard, see above
            log.warning(
                "Failed to acknowledge CTI item after successfully drafting %s (%s); "
                "this item may be re-drafted under a new ID next cycle.",
                hunt_id,
                exc,
            )

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
    athf = AthfClient(
        athf_bin=settings.athf_bin_resolved,
        workspace=settings.athf_workspace,
        env_overrides=settings.env_for_athf(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    cti = get_provider(settings.cti_provider, settings=settings)
    notify = functools.partial(notify_draft_created, settings)
    return Orchestrator(settings=settings, athf=athf, cti_provider=cti, notify=notify)
