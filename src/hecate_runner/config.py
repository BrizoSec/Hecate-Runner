"""Configuration loaded from environment variables (or .env file).

Uses pydantic-settings so config is typed, validated, and self-documenting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the hecate-runner orchestrator."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # ATHF_* and TAVILY_* pass-through env vars are fine to ignore
    )

    # --- ATHF workspace -----------------------------------------------------
    athf_workspace: Path = Field(
        # The ATHF workspace is Hecate-Core. This used to default to
        # ~/agentic-threat-hunting-framework, which no longer exists -- so a
        # deployment with no ATHF_WORKSPACE set resolved athf_bin and
        # cti_queue_dir under a missing directory instead of failing clearly.
        default=Path.home() / "betas" / "Hecate-Core",
        description="Path to the ATHF workspace directory (Hecate-Core)",
    )
    athf_bin: Path | None = Field(
        default=None,
        description="Path to the athf CLI. Defaults to <workspace>/.venv/bin/athf",
    )

    # --- LLM provider (passed through to athf via env) ---------------------
    # Unset by default so the ATHF workspace's own .env owns LLM choice. These
    # used to default to ollama/qwen2.5:7b and were force-passed on every athf
    # call, which silently overrode whatever the workspace had configured --
    # the same two keys were therefore duplicated in both .env files, and
    # editing the workspace copy did nothing while looking like it worked.
    # Set either here only to deliberately override the workspace for
    # orchestrated runs.
    athf_llm_provider: str | None = Field(default=None)
    athf_llm_model: str | None = Field(default=None)

    # --- Orchestrator guardrails -------------------------------------------
    max_drafts_per_day: int = Field(
        default=4,
        ge=1,
        le=100,
        alias="HECATE_RUNNER_MAX_DRAFTS_PER_DAY",
    )
    llm_timeout_sec: int = Field(
        default=1500,
        ge=30,
        le=3600,
        alias="HECATE_RUNNER_LLM_TIMEOUT_SEC",
        description=(
            "Per-subprocess-call timeout for each `athf` invocation (research, "
            "hypothesis-generator, technique lookup). Must comfortably exceed "
            "research_depth's own ceiling (advanced: ~15-20 min) or `athf "
            "research new` gets killed mid-run and the cycle refunds its quota "
            "instead of producing a draft. 1500s (25 min) leaves headroom above "
            "advanced depth's stated ceiling; the systemd unit's own "
            "TimeoutStartSec must be raised to match (see systemd/"
            "hecate-runner-orchestrator.service) since that's an outer, harder cap."
        ),
    )
    cti_provider: Literal["file", "otx", "rss", "misp", "multi"] = Field(
        default="file",
        alias="HECATE_RUNNER_CTI_PROVIDER",
        description=(
            "Which CTI source to use. 'multi' fans out across the sources "
            "listed in HECATE_RUNNER_CTI_MULTI_PROVIDERS."
        ),
    )
    cti_multi_providers_raw: str = Field(
        default="rss,otx,misp",
        alias="HECATE_RUNNER_CTI_MULTI_PROVIDERS",
        description=(
            "Comma-separated sub-provider names to combine when "
            "HECATE_RUNNER_CTI_PROVIDER=multi (from: file, otx, rss, misp — not "
            "'multi' itself). Listed order only matters for the very first "
            "cycle; after that, which source gets first pick round-robins "
            "automatically so one high-volume source can't crowd out the others."
        ),
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        alias="HECATE_RUNNER_LOG_LEVEL",
    )
    cti_queue_dir: Path | None = Field(
        default=None,
        alias="HECATE_RUNNER_CTI_QUEUE_DIR",
        description="CTI queue directory. Defaults to <workspace>/cti_queue.",
    )

    # --- Research grounding (Phase 6) ---------------------------------------
    research_enabled: bool = Field(
        default=True,
        alias="HECATE_RUNNER_RESEARCH_ENABLED",
        description=(
            "Run `athf research new` (web-grounded 5-skill research) before "
            "hypothesis generation. When enabled, a research failure aborts "
            "the cycle (refunds the quota, leaves the CTI queued for retry) "
            "rather than falling back to an ungrounded hypothesis — cold "
            "generation measured ~30% accuracy on known-answer fixtures "
            "(`athf eval`). Set to false to explicitly opt out of research "
            "and always generate ungrounded, e.g. for offline testing."
        ),
    )
    research_depth: Literal["basic", "advanced"] = Field(
        default="advanced",
        alias="HECATE_RUNNER_RESEARCH_DEPTH",
        description=(
            "basic (~5 min) or advanced (~15-20 min, full 5-skill methodology "
            "-- ATHF's own documented default). advanced is the default here "
            "too, on the condition that llm_timeout_sec (this file) and the "
            "systemd unit's TimeoutStartSec (systemd/hecate-runner-orchestrator."
            "service) are both raised to comfortably exceed it -- both have "
            "been. Drop to basic only for time-sensitive/urgent drafting, or "
            "if either of those two ceilings is ever lowered back down."
        ),
    )

    # --- OTX CTI provider -----------------------------------------------------
    otx_api_key: str | None = Field(
        default=None,
        alias="OTX_API_KEY",
        description="AlienVault OTX API key. Required for cti_provider=otx and `hecate-runner otx-poll`.",
    )
    otx_base_url: str = Field(
        default="https://otx.alienvault.com",
        alias="HECATE_RUNNER_OTX_BASE_URL",
    )
    otx_page_limit: int = Field(
        default=20,
        ge=1,
        le=50,
        alias="HECATE_RUNNER_OTX_PAGE_LIMIT",
        description="Pulses fetched per OTX API call.",
    )
    otx_max_pulse_age_days: int = Field(
        default=30,
        ge=1,
        le=365,
        alias="HECATE_RUNNER_OTX_MAX_PULSE_AGE_DAYS",
        description="Ignore pulses created before this many days ago.",
    )
    otx_request_timeout_sec: float = Field(
        default=30.0,
        ge=5.0,
        le=120.0,
        alias="HECATE_RUNNER_OTX_REQUEST_TIMEOUT_SEC",
    )

    # --- RSS CTI provider --------------------------------------------------
    rss_feed_urls_raw: str = Field(
        default=(
            "https://thedfirreport.com/feed/,"
            "https://blog.talosintelligence.com/rss/,"
            "https://unit42.paloaltonetworks.com/feed/,"
            "https://www.microsoft.com/en-us/security/blog/feed/"
        ),
        alias="HECATE_RUNNER_RSS_FEED_URLS",
        description=(
            "Comma-separated RSS/Atom feed URLs. Defaults to four verified, "
            "reputable security research blogs (The DFIR Report, Talos, Unit42, "
            "Microsoft Security Blog) — a curation choice, not a technical "
            "requirement; swap freely. CISA's advisory feed was tried and "
            "excluded: it 403s on automated requests regardless of path."
        ),
    )
    rss_max_entry_age_days: int = Field(
        default=30,
        ge=1,
        le=365,
        alias="HECATE_RUNNER_RSS_MAX_ENTRY_AGE_DAYS",
        description="Ignore entries published before this many days ago.",
    )
    rss_request_timeout_sec: float = Field(
        default=30.0,
        ge=5.0,
        le=120.0,
        alias="HECATE_RUNNER_RSS_REQUEST_TIMEOUT_SEC",
    )

    # --- MISP CTI provider ---------------------------------------------------
    misp_base_url: str | None = Field(
        default=None,
        alias="MISP_BASE_URL",
        description="Base URL of the MISP instance, e.g. https://localhost:8443. Required for cti_provider=misp.",
    )
    misp_api_key: str | None = Field(
        default=None,
        alias="MISP_API_KEY",
        description=(
            "MISP Auth key. Required for cti_provider=misp and `hecate-runner misp-poll`. "
            "Use a dedicated automation key, not a personal user's key."
        ),
    )
    misp_verify_ssl: bool = Field(
        default=True,
        alias="HECATE_RUNNER_MISP_VERIFY_SSL",
        description="Set to false only for self-signed dev/test instances (e.g. a local misp-docker deployment).",
    )
    misp_max_event_age_days: int = Field(
        default=30,
        ge=1,
        le=365,
        alias="HECATE_RUNNER_MISP_MAX_EVENT_AGE_DAYS",
        description="Ignore events published before this many days ago.",
    )
    misp_require_galaxy: bool = Field(
        default=True,
        alias="HECATE_RUNNER_MISP_REQUIRE_GALAXY",
        description=(
            "Only route MISP events carrying a galaxy cluster. Galaxy presence "
            "separates curated, analyst-written events from bulk indicator dumps "
            "(ThreatFox-style), which describe no behavior and can only produce "
            "indicator-sweep drafts with no ATT&CK mapping. Set false for an "
            "instance that does not tag galaxies at all -- otherwise the provider "
            "will correctly find nothing to route."
        ),
    )
    misp_max_pages_per_poll: int = Field(
        default=25,
        ge=1,
        le=500,
        alias="HECATE_RUNNER_MISP_MAX_PAGES_PER_POLL",
        description=(
            "How many event pages one poll may walk before giving up. A run of "
            "rejected events longer than one page is normal on an instance "
            "carrying a daily indicator-dump feed; walking pages within a single "
            "poll is what stops the first backfill candidate taking 25 polls to "
            "reach. Pages are fetched metadata-only, so the cost is small."
        ),
    )
    misp_backfill: bool = Field(
        default=False,
        alias="HECATE_RUNNER_MISP_BACKFILL",
        description=(
            "Ignore the freshness floor and walk the whole MISP archive "
            "oldest-first. For an instance whose useful events predate "
            "misp_max_event_age_days. Reset the cursor file to start from the "
            "beginning; the cursor advances forward each poll and converges back "
            "into normal steady-state behavior once it reaches the present."
        ),
    )
    misp_page_limit: int = Field(
        default=20,
        ge=1,
        le=100,
        alias="HECATE_RUNNER_MISP_PAGE_LIMIT",
        description="Events fetched per restSearch call.",
    )
    misp_request_timeout_sec: float = Field(
        default=30.0,
        ge=5.0,
        le=120.0,
        alias="HECATE_RUNNER_MISP_REQUEST_TIMEOUT_SEC",
    )

    # --- Notifications --------------------------------------------------------
    slack_webhook_url: str | None = Field(
        default=None,
        alias="HECATE_RUNNER_SLACK_WEBHOOK_URL",
        description=(
            "Slack incoming webhook URL. When set, posts a message whenever "
            "the orchestrator creates a draft hunt. Unset = no-op, not an error."
        ),
    )

    # Field names whose values must never appear in `hecate-runner config` output —
    # anyone holding the raw webhook URL can post into the channel, same as
    # an API key.
    _SENSITIVE_FIELDS: ClassVar[set[str]] = {"otx_api_key", "slack_webhook_url", "misp_api_key"}

    # --- Query execution ("propose, don't run") --------------------------------
    query_provider: Literal["mock", "splunk"] = Field(
        default="mock",
        alias="HECATE_RUNNER_QUERY_PROVIDER",
        description=(
            "Backend for `hecate-runner approve`. 'mock' touches nothing real — the "
            "default until real data-source access is configured. 'splunk' "
            "shells out to `athf splunk search` (requires SPLUNK_HOST/SPLUNK_TOKEN "
            "in the ATHF workspace)."
        ),
    )
    max_query_time_range_days: int = Field(
        default=7,
        ge=1,
        le=30,
        alias="HECATE_RUNNER_MAX_QUERY_TIME_RANGE_DAYS",
        description="Hard ceiling on a proposed query's time range. Matches AGENTS.md's Query Guardrails.",
    )
    max_query_limit: int = Field(
        default=1000,
        ge=1,
        le=10000,
        alias="HECATE_RUNNER_MAX_QUERY_LIMIT",
        description="Hard ceiling on a proposed query's result limit. Matches AGENTS.md's Query Guardrails.",
    )

    # --- Derived paths ------------------------------------------------------

    @property
    def athf_bin_resolved(self) -> Path:
        return self.athf_bin or (self.athf_workspace / ".venv" / "bin" / "athf")

    @property
    def cti_queue_dir_resolved(self) -> Path:
        return self.cti_queue_dir or (self.athf_workspace / "cti_queue")

    @property
    def cti_next_file(self) -> Path:
        return self.cti_queue_dir_resolved / "next.txt"

    @property
    def cti_processed_dir(self) -> Path:
        return self.cti_queue_dir_resolved / "processed"

    @property
    def log_dir(self) -> Path:
        return self.athf_workspace / "logs"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "orchestrator.log"

    @property
    def state_file(self) -> Path:
        return self.athf_workspace / ".orchestrator_state.json"

    @property
    def otx_cursor_file(self) -> Path:
        return self.athf_workspace / ".otx_cursor_state.json"

    @property
    def rss_cursor_file(self) -> Path:
        return self.athf_workspace / ".rss_cursor_state.json"

    @property
    def rss_feed_urls(self) -> list[str]:
        """Parsed, whitespace-trimmed feed URL list from HECATE_RUNNER_RSS_FEED_URLS."""
        return [url.strip() for url in self.rss_feed_urls_raw.split(",") if url.strip()]

    @property
    def misp_cursor_file(self) -> Path:
        return self.athf_workspace / ".misp_cursor_state.json"

    @property
    def cti_multi_provider_names(self) -> list[str]:
        """Parsed, whitespace-trimmed sub-provider list from HECATE_RUNNER_CTI_MULTI_PROVIDERS."""
        return [name.strip() for name in self.cti_multi_providers_raw.split(",") if name.strip()]

    @property
    def multi_cursor_file(self) -> Path:
        return self.athf_workspace / ".multi_cti_cursor_state.json"

    @property
    def hunts_root(self) -> Path:
        return self.athf_workspace / "hunts"

    @property
    def pending_queries_dir(self) -> Path:
        return self.athf_workspace / ".pending_queries"

    # --- Validators ---------------------------------------------------------

    @field_validator("athf_workspace")
    @classmethod
    def _expand_workspace(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    def env_for_athf(self) -> dict[str, str]:
        """Env vars to pass through when subprocessing the athf CLI.

        LLM keys are included only when explicitly set. athf calls
        load_dotenv() from the workspace with override=False, so anything
        passed here wins over the workspace's own .env -- omitting the unset
        ones is what lets that file stay authoritative.
        """
        env = {"ATHF_WORKSPACE": str(self.athf_workspace)}
        if self.athf_llm_provider:
            env["ATHF_LLM_PROVIDER"] = self.athf_llm_provider
        if self.athf_llm_model:
            env["ATHF_LLM_MODEL"] = self.athf_llm_model
        return env

    def redacted_dict(self) -> dict[str, Any]:
        """Effective settings with secrets masked — safe to paste into an issue."""
        dumped = self.model_dump(mode="json")
        for field_name in self._SENSITIVE_FIELDS:
            if dumped.get(field_name):
                dumped[field_name] = "<redacted>"
        return dumped
