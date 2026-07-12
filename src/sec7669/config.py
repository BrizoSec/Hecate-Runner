"""Configuration loaded from environment variables (or .env file).

Uses pydantic-settings so config is typed, validated, and self-documenting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the sec7669 orchestrator."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # ATHF_* and TAVILY_* pass-through env vars are fine to ignore
    )

    # --- ATHF workspace -----------------------------------------------------
    athf_workspace: Path = Field(
        default=Path.home() / "agentic-threat-hunting-framework",
        description="Path to the ATHF workspace directory",
    )
    athf_bin: Path | None = Field(
        default=None,
        description="Path to the athf CLI. Defaults to <workspace>/.venv/bin/athf",
    )

    # --- LLM provider (passed through to athf via env) ---------------------
    athf_llm_provider: str = Field(default="ollama")
    athf_llm_model: str = Field(default="qwen2.5:7b-instruct-q4_K_M")

    # --- Orchestrator guardrails -------------------------------------------
    max_drafts_per_day: int = Field(
        default=4,
        ge=1,
        le=100,
        alias="SEC7669_MAX_DRAFTS_PER_DAY",
    )
    llm_timeout_sec: int = Field(
        default=600,
        ge=30,
        le=3600,
        alias="SEC7669_LLM_TIMEOUT_SEC",
    )
    cti_provider: Literal["file", "otx", "rss"] = Field(
        default="file",
        alias="SEC7669_CTI_PROVIDER",
        description="Which CTI source to use.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(
        default="INFO",
        alias="SEC7669_LOG_LEVEL",
    )
    cti_queue_dir: Path | None = Field(
        default=None,
        alias="SEC7669_CTI_QUEUE_DIR",
        description="CTI queue directory. Defaults to <workspace>/cti_queue.",
    )

    # --- Research grounding (Phase 6) ---------------------------------------
    research_enabled: bool = Field(
        default=True,
        alias="SEC7669_RESEARCH_ENABLED",
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
        default="basic",
        alias="SEC7669_RESEARCH_DEPTH",
        description=(
            "basic (~5 min) or advanced (~15-20 min). Keep to basic for an "
            "unattended timer-driven loop unless the LLM timeout and cycle "
            "cadence are both raised to accommodate advanced depth."
        ),
    )

    # --- OTX CTI provider -----------------------------------------------------
    otx_api_key: str | None = Field(
        default=None,
        alias="OTX_API_KEY",
        description="AlienVault OTX API key. Required for cti_provider=otx and `sec7669 otx-poll`.",
    )
    otx_base_url: str = Field(
        default="https://otx.alienvault.com",
        alias="SEC7669_OTX_BASE_URL",
    )
    otx_page_limit: int = Field(
        default=20,
        ge=1,
        le=50,
        alias="SEC7669_OTX_PAGE_LIMIT",
        description="Pulses fetched per OTX API call.",
    )
    otx_max_pulse_age_days: int = Field(
        default=30,
        ge=1,
        le=365,
        alias="SEC7669_OTX_MAX_PULSE_AGE_DAYS",
        description="Ignore pulses created before this many days ago.",
    )
    otx_request_timeout_sec: float = Field(
        default=30.0,
        ge=5.0,
        le=120.0,
        alias="SEC7669_OTX_REQUEST_TIMEOUT_SEC",
    )

    # --- RSS CTI provider --------------------------------------------------
    rss_feed_urls_raw: str = Field(
        default=(
            "https://thedfirreport.com/feed/,"
            "https://blog.talosintelligence.com/rss/,"
            "https://unit42.paloaltonetworks.com/feed/,"
            "https://www.microsoft.com/en-us/security/blog/feed/"
        ),
        alias="SEC7669_RSS_FEED_URLS",
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
        alias="SEC7669_RSS_MAX_ENTRY_AGE_DAYS",
        description="Ignore entries published before this many days ago.",
    )
    rss_request_timeout_sec: float = Field(
        default=30.0,
        ge=5.0,
        le=120.0,
        alias="SEC7669_RSS_REQUEST_TIMEOUT_SEC",
    )

    # --- Notifications --------------------------------------------------------
    slack_webhook_url: str | None = Field(
        default=None,
        alias="SEC7669_SLACK_WEBHOOK_URL",
        description=(
            "Slack incoming webhook URL. When set, posts a message whenever "
            "the orchestrator creates a draft hunt. Unset = no-op, not an error."
        ),
    )

    # Field names whose values must never appear in `sec7669 config` output —
    # anyone holding the raw webhook URL can post into the channel, same as
    # an API key.
    _SENSITIVE_FIELDS: ClassVar[set[str]] = {"otx_api_key", "slack_webhook_url"}

    # --- Query execution ("propose, don't run") --------------------------------
    query_provider: Literal["mock", "splunk"] = Field(
        default="mock",
        alias="SEC7669_QUERY_PROVIDER",
        description=(
            "Backend for `sec7669 approve`. 'mock' touches nothing real — the "
            "default until real data-source access is configured. 'splunk' "
            "shells out to `athf splunk search` (requires SPLUNK_HOST/SPLUNK_TOKEN "
            "in the ATHF workspace)."
        ),
    )
    max_query_time_range_days: int = Field(
        default=7,
        ge=1,
        le=30,
        alias="SEC7669_MAX_QUERY_TIME_RANGE_DAYS",
        description="Hard ceiling on a proposed query's time range. Matches AGENTS.md's Query Guardrails.",
    )
    max_query_limit: int = Field(
        default=1000,
        ge=1,
        le=10000,
        alias="SEC7669_MAX_QUERY_LIMIT",
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
        """Parsed, whitespace-trimmed feed URL list from SEC7669_RSS_FEED_URLS."""
        return [url.strip() for url in self.rss_feed_urls_raw.split(",") if url.strip()]

    @property
    def hunts_root(self) -> Path:
        return self.athf_workspace / "hunts" / "production"

    @property
    def pending_queries_dir(self) -> Path:
        return self.athf_workspace / ".pending_queries"

    # --- Validators ---------------------------------------------------------

    @field_validator("athf_workspace")
    @classmethod
    def _expand_workspace(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    def env_for_athf(self) -> dict[str, str]:
        """Env vars to pass through when subprocessing the athf CLI."""
        return {
            "ATHF_LLM_PROVIDER": self.athf_llm_provider,
            "ATHF_LLM_MODEL": self.athf_llm_model,
            "ATHF_WORKSPACE": str(self.athf_workspace),
        }

    def redacted_dict(self) -> dict[str, Any]:
        """Effective settings with secrets masked — safe to paste into an issue."""
        dumped = self.model_dump(mode="json")
        for field_name in self._SENSITIVE_FIELDS:
            if dumped.get(field_name):
                dumped[field_name] = "<redacted>"
        return dumped
