"""OTX -> CTI queue poller.

Runs on its own, more frequent systemd timer, independent of the main
orchestrator cycle. Pulls at most one high-signal OTX pulse per invocation
and routes it into the file-queue CTI intake (``cti_queue/next.txt``) so the
existing orchestrator picks it up on its normal cadence — this decouples OTX
polling frequency from hypothesis-generation frequency and the daily draft
quota. The queue only has one slot, so if it's already occupied (the
orchestrator hasn't consumed the last item yet) this is a no-op; the same
candidate pulse is retried on the next scheduled poll.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from hecate_runner.config import Settings
from hecate_runner.cti.otx import OtxError, OtxProvider

log = logging.getLogger(__name__)


@dataclass
class OtxPollResult:
    """Structured outcome of one poll cycle."""

    routed: int = 0
    skipped_queue_occupied: bool = False
    error: str | None = None
    routed_pulse_ids: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def run_otx_poll(settings: Settings) -> OtxPollResult:
    """Fetch the next high-signal OTX pulse and route it into the file CTI queue."""
    if not settings.otx_api_key:
        return OtxPollResult(error="OTX_API_KEY is not set")

    queue_dir = settings.cti_queue_dir_resolved
    next_file = queue_dir / "next.txt"
    queue_dir.mkdir(parents=True, exist_ok=True)

    if next_file.exists() and next_file.read_text().strip():
        log.info("CTI queue slot occupied; nothing to do this poll.")
        return OtxPollResult(skipped_queue_occupied=True)

    otx = OtxProvider(
        api_key=settings.otx_api_key,
        cursor_file=settings.otx_cursor_file,
        base_url=settings.otx_base_url,
        page_limit=settings.otx_page_limit,
        max_pulse_age_days=settings.otx_max_pulse_age_days,
        request_timeout_sec=settings.otx_request_timeout_sec,
    )
    result = OtxPollResult()
    try:
        item = otx.next_item()
        if item is None:
            log.info("No new high-signal OTX pulses since last poll.")
            return result

        from hecate_runner.atomic_write import atomic_write_text

        atomic_write_text(next_file, item.content)
        otx.acknowledge(item)
        result.routed = 1
        result.routed_pulse_ids.append(item.identifier)
        log.info(
            "Routed OTX pulse %s (%s) into CTI queue",
            item.identifier,
            item.metadata.get("pulse_name", ""),
        )
    except OtxError as exc:
        log.error("OTX poll failed: %s", exc)
        result.error = str(exc)
    finally:
        otx.close()

    return result
