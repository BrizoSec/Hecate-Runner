"""MISP -> CTI queue poller.

Runs on its own, more frequent systemd timer, independent of the main
orchestrator cycle. Pulls at most one high-signal MISP event per invocation
and routes it into the file-queue CTI intake (``cti_queue/next.txt``) so the
existing orchestrator picks it up on its normal cadence — this decouples
MISP polling frequency from hypothesis-generation frequency and the daily
draft quota. The queue only has one slot, so if it's already occupied (the
orchestrator hasn't consumed the last item yet) this is a no-op; the same
candidate event is retried on the next scheduled poll.

Mirrors otx_poller.py / rss_poller.py structurally.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from hecate_runner.config import Settings
from hecate_runner.cti.misp import MispError, MispProvider

log = logging.getLogger(__name__)


@dataclass
class MispPollResult:
    """Structured outcome of one poll cycle."""

    routed: int = 0
    skipped_queue_occupied: bool = False
    error: str | None = None
    routed_event_uuids: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def run_misp_poll(settings: Settings) -> MispPollResult:
    """Fetch the next high-signal MISP event and route it into the file CTI queue."""
    if not settings.misp_base_url or not settings.misp_api_key:
        return MispPollResult(error="MISP_BASE_URL and MISP_API_KEY must both be set")

    queue_dir = settings.cti_queue_dir_resolved
    next_file = queue_dir / "next.txt"
    queue_dir.mkdir(parents=True, exist_ok=True)

    if next_file.exists() and next_file.read_text().strip():
        log.info("CTI queue slot occupied; nothing to do this poll.")
        return MispPollResult(skipped_queue_occupied=True)

    misp = MispProvider(
        base_url=settings.misp_base_url,
        api_key=settings.misp_api_key,
        cursor_file=settings.misp_cursor_file,
        max_event_age_days=settings.misp_max_event_age_days,
        page_limit=settings.misp_page_limit,
        request_timeout_sec=settings.misp_request_timeout_sec,
        verify_ssl=settings.misp_verify_ssl,
        # These were previously omitted, so `hecate-runner misp-poll` silently
        # ignored the galaxy/backfill/org settings and polled with library
        # defaults -- a standalone poll must select the same events the
        # orchestrator would.
        require_galaxy=settings.misp_require_galaxy,
        require_attack_technique=settings.misp_require_attack_technique,
        org_allowlist=settings.misp_org_allowlist,
        backfill=settings.misp_backfill,
        max_pages_per_poll=settings.misp_max_pages_per_poll,
    )
    result = MispPollResult()
    try:
        item = misp.next_item()
        if item is None:
            log.info("No new high-signal MISP events since last poll.")
            return result

        next_file.write_text(item.content)
        misp.acknowledge(item)
        result.routed = 1
        result.routed_event_uuids.append(item.identifier)
        log.info(
            "Routed MISP event %s (%s) into CTI queue",
            item.identifier,
            item.metadata.get("event_info", ""),
        )
    except MispError as exc:
        log.error("MISP poll failed: %s", exc)
        result.error = str(exc)
    finally:
        misp.close()

    return result
