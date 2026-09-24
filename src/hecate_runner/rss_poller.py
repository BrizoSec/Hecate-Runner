"""RSS -> CTI queue poller.

Runs on its own, more frequent systemd timer, independent of the main
orchestrator cycle. Pulls at most one high-signal RSS/Atom entry (oldest
unrouted, across all configured feeds) per invocation and routes it into
the file-queue CTI intake (``cti_queue/next.txt``) so the existing
orchestrator picks it up on its normal cadence — this decouples RSS polling
frequency from hypothesis-generation frequency and the daily draft quota.
The queue only has one slot, so if it's already occupied (the orchestrator
hasn't consumed the last item yet) this is a no-op; the same candidate
entry is retried on the next scheduled poll.

Mirrors otx_poller.py structurally; kept as a separate module rather than a
generic "cti_poll" because each provider has different failure modes worth
surfacing distinctly (OTX_API_KEY missing vs. zero reachable feeds).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from hecate_runner.config import Settings
from hecate_runner.cti.rss import RssError, RssProvider

log = logging.getLogger(__name__)


@dataclass
class RssPollResult:
    """Structured outcome of one poll cycle."""

    routed: int = 0
    skipped_queue_occupied: bool = False
    error: str | None = None
    routed_entry_ids: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def run_rss_poll(settings: Settings) -> RssPollResult:
    """Fetch the next high-signal RSS/Atom entry and route it into the file CTI queue."""
    if not settings.rss_feed_urls:
        return RssPollResult(error="HECATE_RUNNER_RSS_FEED_URLS has no feed URLs configured")

    queue_dir = settings.cti_queue_dir_resolved
    next_file = queue_dir / "next.txt"
    queue_dir.mkdir(parents=True, exist_ok=True)

    if next_file.exists() and next_file.read_text().strip():
        log.info("CTI queue slot occupied; nothing to do this poll.")
        return RssPollResult(skipped_queue_occupied=True)

    rss = RssProvider(
        feed_urls=settings.rss_feed_urls,
        cursor_file=settings.rss_cursor_file,
        max_entry_age_days=settings.rss_max_entry_age_days,
        request_timeout_sec=settings.rss_request_timeout_sec,
    )
    result = RssPollResult()
    try:
        item = rss.next_item()
        if item is None:
            log.info("No new entries across %d configured RSS feeds.", len(settings.rss_feed_urls))
            return result

        from hecate_runner.atomic_write import atomic_write_text
        atomic_write_text(next_file, item.content)
        rss.acknowledge(item)
        result.routed = 1
        result.routed_entry_ids.append(item.identifier)
        log.info(
            "Routed RSS entry %s (%s) into CTI queue",
            item.identifier,
            item.metadata.get("entry_title", ""),
        )
    except RssError as exc:
        log.error("RSS poll failed: %s", exc)
        result.error = str(exc)
    finally:
        rss.close()

    return result
