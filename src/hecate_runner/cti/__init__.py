"""CTI provider registry."""

from __future__ import annotations

from hecate_runner.config import Settings
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider
from hecate_runner.cti.abuse_ch import AbuseChProvider
from hecate_runner.cti.cisa_kev import CisaKevProvider
from hecate_runner.cti.file_queue import FileQueueProvider
from hecate_runner.cti.misp import MispProvider
from hecate_runner.cti.multi import MultiProvider
from hecate_runner.cti.otx import OtxProvider
from hecate_runner.cti.rss import RssProvider

__all__ = [
    "ATTACK_TECHNIQUE_LINE",
    "CTIItem",
    "CTIProvider",
    "AbuseChProvider",
    "CisaKevProvider",
    "FileQueueProvider",
    "MispProvider",
    "MultiProvider",
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
            require_galaxy=settings.misp_require_galaxy,
            require_attack_technique=settings.misp_require_attack_technique,
            org_allowlist=settings.misp_org_allowlist,
            backfill=settings.misp_backfill,
            max_pages_per_poll=settings.misp_max_pages_per_poll,
        )
    if name == "cisa_kev":
        return CisaKevProvider(workspace=settings.hecate_workspace)
    if name == "abuse_ch":
        return AbuseChProvider(cursor_file=settings.abuse_ch_cursor_file)
    if name == "multi":
        sub_names = settings.cti_multi_provider_names
        if not sub_names:
            raise ValueError(
                "HECATE_RUNNER_CTI_MULTI_PROVIDERS must list at least one provider when HECATE_RUNNER_CTI_PROVIDER=multi"
            )
        if "multi" in sub_names:
            raise ValueError("HECATE_RUNNER_CTI_MULTI_PROVIDERS cannot include 'multi' itself")
        sub_providers = [get_provider(sub_name, settings=settings) for sub_name in sub_names]
        return MultiProvider(providers=sub_providers, cursor_file=settings.multi_cursor_file)
    raise ValueError(f"Unknown CTI provider: {name!r}")
