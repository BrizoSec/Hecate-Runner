"""CTI provider registry."""

from __future__ import annotations

from hecate_runner.config import Settings
from hecate_runner.cti.abuse_ch import AbuseChProvider
from hecate_runner.cti.anyrun import AnyRunProvider
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider
from hecate_runner.cti.censys_c2 import CensysC2Provider
from hecate_runner.cti.certstream import CertStreamProvider
from hecate_runner.cti.cisa_kev import CisaKevProvider
from hecate_runner.cti.cloud_threat import CloudThreatProvider
from hecate_runner.cti.dfir_report import DfirReportProvider
from hecate_runner.cti.file_queue import FileQueueProvider
from hecate_runner.cti.first_org import FirstOrgProvider
from hecate_runner.cti.github_poc import GitHubPocProvider
from hecate_runner.cti.malwarebazaar import MalwareBazaarProvider
from hecate_runner.cti.misp import MispProvider
from hecate_runner.cti.msrc import MsrcProvider
from hecate_runner.cti.multi import MultiProvider
from hecate_runner.cti.opencti import OpenCTIProvider
from hecate_runner.cti.otx import OtxProvider
from hecate_runner.cti.rss import RssProvider
from hecate_runner.cti.shadowserver import ShadowserverProvider
from hecate_runner.cti.triage import TriageProvider
from hecate_runner.cti.vulncheck import VulnCheckProvider
from hecate_runner.cti.vxunderground import VxUndergroundProvider

__all__ = [
    "ATTACK_TECHNIQUE_LINE",
    "AbuseChProvider",
    "AnyRunProvider",
    "CTIItem",
    "CTIProvider",
    "CensysC2Provider",
    "CertStreamProvider",
    "CisaKevProvider",
    "CloudThreatProvider",
    "DfirReportProvider",
    "FileQueueProvider",
    "FirstOrgProvider",
    "GitHubPocProvider",
    "MalwareBazaarProvider",
    "MispProvider",
    "MsrcProvider",
    "MultiProvider",
    "OpenCTIProvider",
    "OtxProvider",
    "RssProvider",
    "ShadowserverProvider",
    "TriageProvider",
    "VulnCheckProvider",
    "VxUndergroundProvider",
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
    if name == "certstream":
        return CertStreamProvider(
            cursor_file=settings.certstream_cursor_file,
            stream_url=settings.certstream_stream_url,
            brand_patterns=settings.certstream_brand_patterns,
            suspicious_keywords=settings.certstream_suspicious_keywords,
            poll_timeout_sec=settings.certstream_poll_timeout_sec,
            max_buffer_size=settings.certstream_max_buffer_size,
        )
    if name == "github_poc":
        return GitHubPocProvider(
            workspace=settings.hecate_workspace,
            github_token=settings.github_token,
            cursor_file=settings.github_poc_cursor_file,
            request_timeout_sec=settings.github_poc_request_timeout_sec,
            min_stars=settings.github_poc_min_stars,
        )
    if name == "malwarebazaar":
        return MalwareBazaarProvider(
            workspace=settings.hecate_workspace,
            api_key=settings.abusech_api_key,
            cursor_file=settings.malwarebazaar_cursor_file,
            request_timeout_sec=settings.malwarebazaar_request_timeout_sec,
            only_signed=settings.malwarebazaar_only_signed,
        )
    if name == "vxunderground":
        return VxUndergroundProvider(
            workspace=settings.hecate_workspace,
            github_token=settings.github_token,
            cursor_file=settings.vxunderground_cursor_file,
            request_timeout_sec=settings.vxunderground_request_timeout_sec,
        )
    if name == "dfir_report":
        return DfirReportProvider(
            cursor_file=settings.dfir_report_cursor_file,
            feed_url=settings.dfir_report_feed_url,
            max_entry_age_days=settings.dfir_report_max_entry_age_days,
            request_timeout_sec=settings.dfir_report_request_timeout_sec,
        )
    if name == "triage":
        return TriageProvider(
            cursor_file=settings.triage_cursor_file,
            api_key=settings.triage_api_key,
            search_query=settings.triage_search_query,
            request_timeout_sec=settings.triage_request_timeout_sec,
        )
    if name == "vulncheck":
        return VulnCheckProvider(
            cursor_file=settings.vulncheck_cursor_file,
            api_key=settings.vulncheck_api_key,
            max_age_days=settings.vulncheck_max_age_days,
            request_timeout_sec=settings.vulncheck_request_timeout_sec,
        )
    if name == "censys_c2":
        return CensysC2Provider(
            cursor_file=settings.censys_c2_cursor_file,
            api_token=settings.censys_api_token,
            query=settings.censys_c2_query,
            request_timeout_sec=settings.censys_c2_request_timeout_sec,
        )
    if name == "shadowserver":
        return ShadowserverProvider(
            cursor_file=settings.shadowserver_cursor_file,
            api_key=settings.shadowserver_api_key,
            api_secret=settings.shadowserver_api_secret,
            request_timeout_sec=settings.shadowserver_request_timeout_sec,
        )
    if name == "msrc":
        return MsrcProvider(
            cursor_file=settings.msrc_cursor_file,
            updates_url=settings.msrc_updates_url,
            doc_base_url=settings.msrc_doc_base_url,
            max_age_days=settings.msrc_max_age_days,
            request_timeout_sec=settings.msrc_request_timeout_sec,
        )
    if name == "cloud_threat":
        return CloudThreatProvider(
            cursor_file=settings.cloud_threat_cursor_file,
            feed_urls=settings.cloud_threat_feed_urls,
            max_entry_age_days=settings.cloud_threat_max_entry_age_days,
            request_timeout_sec=settings.cloud_threat_request_timeout_sec,
        )
    if name == "first_org":
        return FirstOrgProvider(
            cursor_file=settings.first_org_cursor_file,
            base_url=settings.first_org_base_url,
            min_epss=settings.first_org_min_epss,
            min_percentile=settings.first_org_min_percentile,
            limit=settings.first_org_limit,
            request_timeout_sec=settings.first_org_request_timeout_sec,
        )
    if name == "anyrun":
        return AnyRunProvider(
            cursor_file=settings.anyrun_cursor_file,
            api_key=settings.anyrun_api_key,
            api_url=settings.anyrun_api_url,
            feed_url=settings.anyrun_feed_url,
            max_age_days=settings.anyrun_max_age_days,
            request_timeout_sec=settings.anyrun_request_timeout_sec,
        )
    if name == "opencti":
        return OpenCTIProvider(
            cursor_file=settings.opencti_cursor_file,
            base_url=settings.opencti_url,
            api_token=settings.opencti_token,
            limit=settings.opencti_limit,
            request_timeout_sec=settings.opencti_request_timeout_sec,
        )
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
