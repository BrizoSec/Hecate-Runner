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

from sec7669.athf_client import AthfClient, AthfError
from sec7669.config import Settings
from sec7669.cti import CTIProvider, get_provider
from sec7669.hunt_writer import DraftHuntRequest, hunt_id_lock, next_hunt_id, write_draft
from sec7669.notifications import notify_draft_created
from sec7669.state import OrchestratorState

log = logging.getLogger(__name__)

# MITRE technique IDs embedded in raw CTI text, e.g. "T1003.001" or "T1053.005".
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# `athf research new --topic` expects a short label, not a raw CTI paragraph.
_TOPIC_MAX_LEN = 100


def derive_research_topic(cti_content: str) -> tuple[str, str | None]:
    """Best-effort (topic, technique) pair from a raw CTI blob.

    No NLP here on purpose — this only has to be good enough to seed the
    research agent's web searches; the research + hypothesis steps do the
    actual analysis.
    """
    technique_match = _TECHNIQUE_RE.search(cti_content)
    technique = technique_match.group(0) if technique_match else None

    topic = " ".join(cti_content.split()).strip()
    if len(topic) > _TOPIC_MAX_LEN:
        truncated = topic[:_TOPIC_MAX_LEN]
        # Prefer cutting on a word boundary so we don't hand the agent a
        # half-word topic.
        if " " in truncated:
            truncated = truncated.rsplit(" ", 1)[0]
        topic = truncated
    return topic or "Untitled CTI", technique


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
        """
        tactics: list[str] = []
        platforms: list[str] = []
        for technique_id in techniques:
            meta = self.athf.lookup_technique(technique_id, timeout_sec=self.settings.llm_timeout_sec)
            for tactic in meta.tactics:
                if tactic not in tactics:
                    tactics.append(tactic)
            for platform in meta.platforms:
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

        research_id: str | None = None
        if self.settings.research_enabled:
            topic, technique = derive_research_topic(item.content)
            try:
                research_result = self.athf.research_new(
                    topic=topic,
                    technique=technique,
                    depth=self.settings.research_depth,
                    timeout_sec=self.settings.llm_timeout_sec,
                )
            except AthfError as exc:
                # Cold (ungrounded) generation measured ~30% accuracy on known-
                # answer fixtures (see `athf eval`) — a research failure is
                # refused rather than silently falling back to that. Refund
                # the quota; the CTI stays in the queue for the next cycle.
                log.error("athf research new failed (%s); refusing to generate an ungrounded hypothesis", exc)
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="research_error", detail=str(exc))

            if research_result.is_empty:
                log.error("athf research new produced no research_id; refusing to generate an ungrounded hypothesis")
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="research_empty")

            research_id = research_result.research_id
            log.info("Research %s grounds this cycle's hypothesis", research_id)

        try:
            hypothesis = self.athf.hypothesis_generator(
                threat_intel=item.content,
                research_id=research_id,
                timeout_sec=self.settings.llm_timeout_sec,
            )
        except AthfError as exc:
            log.error("athf hypothesis-generator failed: %s", exc)
            # Refund the quota — the CTI stays in the queue.
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="athf_error", detail=str(exc))

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
            hunt_id, path, research_id or "none", state.drafts_today, self.settings.max_drafts_per_day,
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
            log.warning("Draft-created notification failed (%s); draft %s was still created", exc, hunt_id)

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
