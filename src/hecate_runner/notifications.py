"""Notification hooks — best-effort alerts when the orchestrator produces a draft.

A notification failure must never cost a draft or fail the cycle: every
function here catches its own errors and logs a warning instead of raising.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from hecate_runner.config import Settings

if TYPE_CHECKING:
    from hecate_runner.orchestrator import RunResult

log = logging.getLogger(__name__)


def notify_draft_created(settings: Settings, result: RunResult) -> None:
    """Post a Slack message for a newly created draft. No-op if unconfigured."""
    if not settings.slack_webhook_url:
        return

    research_context = (
        f"research context {result.research_id}" if result.research_id else "no research context"
    )
    parked_note = (
        f"\n:information_source: {result.parked_count} item(s) were held back (parked) during intake triage."
        if result.parked_count > 0
        else ""
    )
    text = (
        f":memo: New draft hunt *{result.hunt_id}* ({research_context})\n"
        f"`{result.draft_path}`\n"
        f"Status: `planning` — human review required before execution.{parked_note}"
    )

    try:
        response = httpx.post(settings.slack_webhook_url, json={"text": text}, timeout=10.0)
        response.raise_for_status()
    except Exception as exc:
        # Deliberately broad, not just httpx.HTTPError: a malformed
        # HECATE_RUNNER_SLACK_WEBHOOK_URL raises httpx.InvalidURL, which inherits
        # directly from Exception, not HTTPError -- narrower except clauses
        # here would violate this module's own stated contract ("every
        # function here catches its own errors ... instead of raising").
        # Currently double-covered by orchestrator.py's own broad catch
        # around self.notify(result), but this module shouldn't rely on its
        # caller to keep a promise it makes itself.
        log.warning("Slack notification failed (%s); draft was still created successfully", exc)


def send_test_notification(settings: Settings) -> tuple[bool, str]:
    """Send a test message to verify the Slack webhook. Returns (success, message)."""
    if not settings.slack_webhook_url:
        return False, "HECATE_RUNNER_SLACK_WEBHOOK_URL is not configured."

    text = (
        ":white_check_mark: *Hecate Pipeline Notification Test*\n"
        "Slack webhook connectivity verified successfully from Hecate-Runner."
    )
    try:
        response = httpx.post(settings.slack_webhook_url, json={"text": text}, timeout=10.0)
        response.raise_for_status()
        return True, "Notification sent successfully."
    except Exception as exc:
        return False, f"Slack notification failed: {exc}"
