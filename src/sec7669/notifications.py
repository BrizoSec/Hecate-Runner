"""Notification hooks — best-effort alerts when the orchestrator produces a draft.

A notification failure must never cost a draft or fail the cycle: every
function here catches its own errors and logs a warning instead of raising.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from sec7669.config import Settings

if TYPE_CHECKING:
    from sec7669.orchestrator import RunResult

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
    except httpx.HTTPError as exc:
        log.warning("Slack notification failed (%s); draft was still created successfully", exc)
