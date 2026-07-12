"""CTI provider registry."""

from __future__ import annotations

from sec7669.config import Settings
from sec7669.cti.base import CTIItem, CTIProvider
from sec7669.cti.file_queue import FileQueueProvider
from sec7669.cti.misp import MispProvider
from sec7669.cti.otx import OtxProvider
from sec7669.cti.rss import RssProvider

__all__ = [
    "CTIItem",
    "CTIProvider",
    "FileQueueProvider",
    "MispProvider",
    "OtxProvider",
    "RssProvider",
    "get_provider",
]


def get_provider(name: str, *, settings: Settings) -> CTIProvider:
    """Factory that returns a CTI provider by name."""
    if name == "file":
        return FileQueueProvider(queue_dir=settings.cti_queue_dir_resolved)
    if name == "otx":
        return OtxProvider(
            api_key=settings.otx_api_key or "",
            cursor_file=settings.otx_cursor_file,
            base_url=settings.otx_base_url,
            page_limit=settings.otx_page_limit,
            max_pulse_age_days=settings.otx_max_pulse_age_days,
            request_timeout_sec=settings.otx_request_timeout_sec,
        )
    if name == "rss":
        return RssProvider(
            feed_urls=settings.rss_feed_urls,
            cursor_file=settings.rss_cursor_file,
            max_entry_age_days=settings.rss_max_entry_age_days,
            request_timeout_sec=settings.rss_request_timeout_sec,
        )
    if name == "misp":
        return MispProvider(
            base_url=settings.misp_base_url or "",
            api_key=settings.misp_api_key or "",
            cursor_file=settings.misp_cursor_file,
            max_event_age_days=settings.misp_max_event_age_days,
            page_limit=settings.misp_page_limit,
            request_timeout_sec=settings.misp_request_timeout_sec,
            verify_ssl=settings.misp_verify_ssl,
        )
    raise ValueError(f"Unknown CTI provider: {name!r}")
