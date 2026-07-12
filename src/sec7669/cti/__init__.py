"""CTI provider registry."""

from __future__ import annotations

from sec7669.config import Settings
from sec7669.cti.base import CTIItem, CTIProvider
from sec7669.cti.file_queue import FileQueueProvider
from sec7669.cti.otx import OtxProvider

__all__ = ["CTIItem", "CTIProvider", "FileQueueProvider", "OtxProvider", "get_provider"]


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
    raise ValueError(f"Unknown CTI provider: {name!r}")
