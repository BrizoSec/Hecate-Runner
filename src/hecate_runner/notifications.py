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

    grounding = f"grounded by {result.research_id}" if result.research_id else "ungrounded"
    text = (
        f":memo: New draft hunt *{result.hunt_id}* ({grounding})\n"
        f"`{result.draft_path}`\n"
        f"Status: `planning` — human review required before execution."
    )

    try:
        response = httpx.post(settings.slack_webhook_url, json={"text": text}, timeout=10.0)
        response.raise_for_status()
    except Exception as exc:
        # Deliberately broad, not just httpx.HTTPError: a malformed
        # SEC7669_SLACK_WEBHOOK_URL raises httpx.InvalidURL, which inherits
        # directly from Exception, not HTTPError -- narrower except clauses
        # here would violate this module's own stated contract ("every
        # function here catches its own errors ... instead of raising").
        # Currently double-covered by orchestrator.py's own broad catch
        # around self.notify(result), but this module shouldn't rely on its
        # caller to keep a promise it makes itself.
        log.warning("Slack notification failed (%s); draft was still created successfully", exc)
