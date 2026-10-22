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
        extra="ignore",  # HECATE_* and TAVILY_* pass-through env vars are fine to ignore
        populate_by_name=True,
    )

    # --- Hecate workspace -----------------------------------------------------
    hecate_workspace: Path = Field(
        # The Hecate workspace is Hecate-Core. This used to default to
        # ~/agentic-threat-hunting-framework, which no longer exists -- so a
        # deployment with no HECATE_WORKSPACE set resolved hecate_bin and
        # cti_queue_dir under a missing directory instead of failing clearly.
        default=Path.home() / "betas" / "Hecate-Workspace",
        description="Path to the Hecate workspace directory (Hecate-Workspace)",
    )
    hecate_bin: Path | None = Field(
        default=None,
        description="Path to the hecate-agent CLI. Defaults to <workspace>/.venv/bin/hecate-agent",
    )

    # --- LLM provider (passed through to hecate via env) ---------------------
    # Unset by default so the Hecate workspace's own .env owns LLM choice. These
    # used to default to ollama/qwen2.5:7b and were force-passed on every hecate
    # call, which silently overrode whatever the workspace had configured --
    # the same two keys were therefore duplicated in both .env files, and
    # editing the workspace copy did nothing while looking like it worked.
    # Set either here only to deliberately override the workspace for
    # orchestrated runs.
    hecate_llm_provider: str | None = Field(default=None)
    hecate_llm_model: str | None = Field(default=None)

    # --- Orchestrator guardrails -------------------------------------------
    max_drafts_per_day: int = Field(
        default=2,
        ge=1,
        le=100,
        alias="HECATE_RUNNER_MAX_DRAFTS_PER_DAY",
    )
    max_research_runs_per_day: int = Field(
        default=3,
        ge=0,
        le=100,
        alias="HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY",
        description=(
            "Cap on web-searching research runs per UTC day. Each run makes two "
            "Tavily searches (4 credits at advanced depth, 2 at basic). Unlike "
            "the draft quota this is never refunded, so a cycle that fails after "
            "research and retries cannot keep spending credits. 0 blocks all searched research."
        ),
    )
    min_hours_between_drafts: float = Field(
        default=6.0,
        ge=0.0,
        le=72.0,
        alias="HECATE_RUNNER_MIN_HOURS_BETWEEN_DRAFTS",
        description=(
            "Minimum spacing in hours between automatic draft creation runs. "
            "Prevents back-to-back runs from exhausting daily quota in the early "
            "hours of the day. 0 disables spacing."
        ),
    )
    llm_timeout_sec: int = Field(
        default=1500,
        ge=30,
        le=3600,
        alias="HECATE_RUNNER_LLM_TIMEOUT_SEC",
        description=(
            "Per-subprocess-call timeout for each `hecate-agent` invocation (research, "
            "hypothesis-generator, technique lookup). Must comfortably exceed "
            "research_depth's own ceiling (advanced: ~15-20 min) or `hecate "
            "research new` gets killed mid-run and the cycle refunds its quota "
            "instead of producing a draft. 1500s (25 min) leaves headroom above "
            "advanced depth's stated ceiling; the systemd unit's own "
            "TimeoutStartSec must be raised to match (see systemd/"
            "hecate-runner-orchestrator.service) since that's an outer, harder cap."
        ),
    )
    cti_provider: Literal[
        "file",
        "otx",
        "rss",
        "misp",
        "cisa_kev",
        "abuse_ch",
        "certstream",
        "github_poc",
        "malwarebazaar",
        "vxunderground",
        "multi",
    ] = Field(
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
    log_max_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=0,
        alias="HECATE_RUNNER_LOG_MAX_BYTES",
        description=(
            "Rotate the orchestrator log once it exceeds this size, checked at "
            "the start of every run. 0 disables rotation. Rotation copies the "
            "file aside and truncates it in place rather than renaming it, "
            "because systemd also holds this file open (StandardOutput=append:) "
            "and a rename would leave it writing to the archive."
        ),
    )
    log_backup_count: int = Field(
        default=5,
        ge=0,
        alias="HECATE_RUNNER_LOG_BACKUP_COUNT",
        description=(
            "How many rotated logs to keep (orchestrator.log.1 … .N). 0 keeps "
            "none, truncating without history."
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
    parked_max_age_days: int = Field(
        default=30,
        alias="HECATE_RUNNER_PARKED_MAX_AGE_DAYS",
        description="Days after which parked CTI items are automatically deleted. 0 to disable.",
    )

    # --- Research grounding (Phase 6) ---------------------------------------
    sigma_review_enabled: bool = Field(
        default=True,
        alias="HECATE_RUNNER_SIGMA_REVIEW_ENABLED",
        description=(
            "Review each model-drafted Sigma rule against the hypothesis and the "
            "verified source passages, and list behaviours no rule covers. A rule is "
            "dropped only for a contradiction the reviewer quotes verbatim from the "
            "source. Costs one model call per model rule plus one."
        ),
    )
    source_evidence_enabled: bool = Field(
        default=True,
        alias="HECATE_RUNNER_SOURCE_EVIDENCE_ENABLED",
        description=(
            "Fetch the report a CTI item links to and extract artifacts verified "
            "verbatim against it (process tree, paths, ports, and each indicator's "
            "role and current-versus-historical status) before research and "
            "drafting. A failed fetch drafts from the feed item as before. Adds a "
            "few local-model calls per cycle; set false to skip."
        ),
    )
    research_enabled: bool = Field(
        default=True,
        alias="HECATE_RUNNER_RESEARCH_ENABLED",
        description=(
            "Run `hecate-agent research new` (web-grounded 5-skill research) before "
            "hypothesis generation. When enabled, a research failure aborts "
            "the cycle (refunds the quota, leaves the CTI queued for retry) "
            "rather than falling back to an ungrounded hypothesis — cold "
            "generation measured ~30% accuracy on known-answer fixtures "
            "(`hecate-agent eval`). Set to false to explicitly opt out of research "
            "and always generate ungrounded, e.g. for offline testing."
        ),
    )
    sigma_generation_enabled: bool = Field(
        default=True,
        alias="HECATE_RUNNER_SIGMA_GENERATION_ENABLED",
        description=(
            "Draft Sigma detection rules for each applicable log source after "
            "the hypothesis, so an operator reviews a hunt that already has "
            "candidate queries. Rules are proposals only — nothing is ever "
            "executed from them, and Sigma is platform-neutral, so this "
            "commits to no query language. A failure here leaves the draft "
            "standing with its placeholder query section rather than losing "
            "the hunt, so disabling this only removes the section."
        ),
    )
    purple_team_validation_enabled: bool = Field(
        default=True,
        alias="HECATE_RUNNER_PURPLE_TEAM_VALIDATION_ENABLED",
        description=(
            "Run closed-loop sandbox emulation and detection self-tuning on all "
            "generated Sigma detection rules before finalizing the hunt package."
        ),
    )
    sigma_timeout_sec: int = Field(
        default=1800,
        ge=30,
        alias="HECATE_RUNNER_SIGMA_TIMEOUT_SEC",
        description=(
            "Timeout for the whole Sigma drafting subprocess. Generous because "
            "drafting makes one LLM call per applicable log source, and a hunt "
            "can apply to six -- so the worst case is six model timeouts back "
            "to back, not one. Each individual call is bounded by "
            "HECATE_OLLAMA_TIMEOUT_SEC in the workspace .env."
        ),
    )
    research_depth: Literal["basic", "advanced"] = Field(
        default="advanced",
        alias="HECATE_RUNNER_RESEARCH_DEPTH",
        description=(
            "basic (~5 min) or advanced (~15-20 min, full 5-skill methodology "
            "-- Hecate's own documented default). advanced is the default here "
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
            "https://www.microsoft.com/en-us/security/blog/feed/,"
            "https://blog.google/threat-analysis-group/rss/,"
            "https://www.mandiant.com/resources/blog/rss.xml,"
            "https://blog.sekoia.io/feed/,"
            "https://www.volexity.com/blog/feed/,"
            "https://www.welivesecurity.com/feed/"
        ),
        alias="HECATE_RUNNER_RSS_FEED_URLS",
        description=(
            "Comma-separated RSS/Atom feed URLs. Defaults to nine verified, "
            "reputable security research blogs (The DFIR Report, Talos, Unit42, "
            "Microsoft Security Blog, Google TAG, Mandiant, Sekoia, Volexity, "
            "WeLiveSecurity) — a curation choice, not a technical "
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
    misp_require_attack_technique: bool = Field(
        default=False,
        alias="HECATE_RUNNER_MISP_REQUIRE_ATTACK_TECHNIQUE",
        description=(
            "Only route MISP events that map to at least one ATT&CK technique. "
            "Stricter than misp_require_galaxy, which is satisfied by any "
            "galaxy cluster: an event tagged only with a threat-actor or "
            "malware galaxy has a cluster but no attack-pattern, so it yields "
            "no technique IDs and can only produce an indicator-sweep draft. "
            "Off by default because a sweep is still useful output; turn it on "
            "to route only events a behavioural hunt can be built from."
        ),
    )
    misp_org_allowlist_raw: str = Field(
        default="",
        alias="HECATE_RUNNER_MISP_ORG_ALLOWLIST",
        description=(
            "Comma-separated MISP organisation names; when set, only events "
            "from these orgs are routable. Empty (the default) means every org "
            "is eligible. This is a restriction, not a ranking: an instance "
            "dominated by one high-volume feed can otherwise bury the handful "
            "of analyst-written events behind hundreds of drafts. Matching is "
            "case-insensitive on the owning (Orgc) organisation. Note that "
            "excluded events are walked past permanently -- the cursor advances "
            "over them -- so widen the list before backfilling, not after."
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

    # --- CertStream CTI provider -------------------------------------------
    certstream_stream_url: str = Field(
        default="wss://certstream.calidog.io/",
        alias="HECATE_RUNNER_CERTSTREAM_URL",
        description="CertStream WebSocket URL for real-time Certificate Transparency log streaming.",
    )
    certstream_brand_patterns_raw: str = Field(
        default="apple,notion,google,microsoft,github,binance,metamask,trezor,ledger,paypal,coinbase,phantom",
        alias="HECATE_RUNNER_CERTSTREAM_BRANDS",
        description="Comma-separated list of target brand names to monitor for typosquatting / impersonation.",
    )
    certstream_suspicious_keywords_raw: str = Field(
        default="download,update,login,verify,auth,support,security,wallet,app,token,claim,airdrop,setup,install",
        alias="HECATE_RUNNER_CERTSTREAM_KEYWORDS",
        description="Comma-separated list of suspicious staging or lure keywords.",
    )
    certstream_poll_timeout_sec: float = Field(
        default=5.0,
        ge=0.5,
        le=60.0,
        alias="HECATE_RUNNER_CERTSTREAM_POLL_TIMEOUT_SEC",
        description="Timeout in seconds when polling the live CertStream websocket.",
    )
    certstream_max_buffer_size: int = Field(
        default=100,
        ge=1,
        le=1000,
        alias="HECATE_RUNNER_CERTSTREAM_MAX_BUFFER",
        description="Maximum number of candidate staging items to buffer in memory.",
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

    # --- Auxiliary CTI & Enrichment keys --------------------------------------
    urlscan_api_key: str | None = Field(
        default=None,
        alias="URLSCAN_API_KEY",
        description="URLScan.io API key for on-demand detonation and search.",
    )
    spur_api_key: str | None = Field(
        default=None,
        alias="SPUR_API_KEY",
        description="Spur.us Context API token for IP anonymity and proxy intelligence.",
    )
    mnemonic_api_key: str | None = Field(
        default=None,
        alias="MNEMONIC_API_KEY",
        description="Mnemonic Argus API key for passive DNS queries (optional; public queries work keylessly).",
    )
    ipinfo_token: str | None = Field(
        default=None,
        alias="IPINFO_TOKEN",
        description="IPinfo.io API token (free community tier allows 50,000 queries/month).",
    )
    github_token: str | None = Field(
        default=None,
        alias="GITHUB_TOKEN",
        description="GitHub personal access token for higher Search API rate limits.",
    )
    github_publishing_enabled: bool = Field(
        default=False,
        alias="HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED",
        description="Publish completed planning hunts as isolated pull requests to Hecate-Content.",
    )
    github_app_id: str | None = Field(
        default=None,
        alias="HECATE_RUNNER_GITHUB_APP_ID",
        description="GitHub App ID used only for content publication.",
    )
    github_installation_id: str | None = Field(
        default=None,
        alias="HECATE_RUNNER_GITHUB_INSTALLATION_ID",
        description="GitHub App installation ID for the target content repository.",
    )
    github_app_slug: str = Field(
        default="hecate-publisher",
        alias="HECATE_RUNNER_GITHUB_APP_SLUG",
        description="GitHub App slug; used to attribute generated Git commits to the publisher bot.",
    )
    github_app_private_key_path: Path | None = Field(
        default=None,
        alias="HECATE_RUNNER_GITHUB_APP_PRIVATE_KEY_PATH",
        description="Mounted PEM file for the publishing GitHub App; never store the key in .env.",
    )
    github_publishing_repository: str = Field(
        default="BrizoSec/Hecate-Content",
        alias="HECATE_RUNNER_GITHUB_PUBLISHING_REPOSITORY",
        description="Owner/repository for generated hunt pull requests.",
    )
    github_publishing_base_branch: str = Field(
        default="main",
        alias="HECATE_RUNNER_GITHUB_PUBLISHING_BASE_BRANCH",
        description="Protected target branch for generated hunt pull requests.",
    )
    github_poc_request_timeout_sec: float = Field(
        default=10.0,
        ge=3.0,
        le=60.0,
        alias="HECATE_RUNNER_GITHUB_POC_TIMEOUT_SEC",
        description="Timeout for GitHub API and raw repository requests.",
    )
    github_poc_min_stars: int = Field(
        default=0,
        ge=0,
        alias="HECATE_RUNNER_GITHUB_POC_MIN_STARS",
        description="Minimum stars required for GitHub PoC repositories.",
    )
    abusech_api_key: str | None = Field(
        default=None,
        alias="ABUSECH_API_KEY",
        description="Abuse.ch Auth-Key for MalwareBazaar and ThreatFox.",
    )
    malwarebazaar_only_signed: bool = Field(
        default=True,
        alias="HECATE_RUNNER_MALWAREBAZAAR_ONLY_SIGNED",
        description="Filter for samples with identified malware families.",
    )
    malwarebazaar_request_timeout_sec: float = Field(
        default=15.0,
        ge=3.0,
        le=60.0,
        alias="HECATE_RUNNER_MALWAREBAZAAR_TIMEOUT_SEC",
        description="Timeout for MalwareBazaar requests.",
    )
    vxunderground_request_timeout_sec: float = Field(
        default=15.0,
        ge=3.0,
        le=60.0,
        alias="HECATE_RUNNER_VXUNDERGROUND_TIMEOUT_SEC",
        description="Timeout for VX-Underground requests.",
    )

    # Field names whose values must never appear in `hecate-runner config` output —
    # anyone holding the raw webhook URL can post into the channel, same as
    # an API key.
    _SENSITIVE_FIELDS: ClassVar[set[str]] = {
        "otx_api_key",
        "slack_webhook_url",
        "misp_api_key",
        "urlscan_api_key",
        "spur_api_key",
        "mnemonic_api_key",
        "ipinfo_token",
        "github_token",
        "github_app_id",
        "github_installation_id",
        "github_app_private_key_path",
        "abusech_api_key",
    }

    # --- CTI intake triage ----------------------------------------------------
    cti_triage: Literal["park", "off"] = Field(
        default="park",
        alias="HECATE_RUNNER_CTI_TRIAGE",
        description=(
            "Hold back CTI that is commentary rather than intelligence -- a "
            "conference recap, a weekly news roundup, a product post. 'park' "
            "writes such items whole to <cti_queue>/parked/ with the reason "
            "attached, where `hecate-runner parked` lists them and "
            "`hecate-runner parked restore <id>` puts one back; nothing is "
            "ever discarded, which is what makes gating on a heuristic "
            "acceptable. 'off' drafts from everything, the behaviour before "
            "this existed."
        ),
    )

    # --- Query execution ("propose, don't run") --------------------------------
    query_provider: Literal["mock", "splunk"] = Field(
        default="mock",
        alias="HECATE_RUNNER_QUERY_PROVIDER",
        description=(
            "Backend for `hecate-runner approve`. 'mock' touches nothing real — the "
            "default until real data-source access is configured. 'splunk' "
            "shells out to `hecate-agent splunk search` (requires SPLUNK_HOST/SPLUNK_TOKEN "
            "in the Hecate workspace)."
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
    def hecate_bin_resolved(self) -> Path:
        return self.hecate_bin or (self.hecate_workspace / ".venv" / "bin" / "hecate-agent")

    @property
    def cti_queue_dir_resolved(self) -> Path:
        return self.cti_queue_dir or (self.hecate_workspace / "cti_queue")

    @property
    def cti_next_file(self) -> Path:
        return self.cti_queue_dir_resolved / "next.txt"

    @property
    def log_dir(self) -> Path:
        return self.hecate_workspace / "logs"

    @property
    def log_file(self) -> Path:
        return self.log_dir / "orchestrator.log"

    @property
    def metrics_file(self) -> Path:
        """Append-only per-cycle stage metrics used by `hecate-runner metrics`."""
        return self.log_dir / "stage_metrics.jsonl"

    @property
    def llm_calls_file(self) -> Path:
        """The running cycle's provider calls, written by Core as each starts and ends."""
        return self.log_dir / "llm_calls.jsonl"

    @property
    def state_file(self) -> Path:
        return self.hecate_workspace / ".orchestrator_state.json"

    @property
    def otx_cursor_file(self) -> Path:
        return self.hecate_workspace / ".otx_cursor_state.json"

    @property
    def rss_cursor_file(self) -> Path:
        return self.hecate_workspace / ".rss_cursor_state.json"

    @property
    def rss_feed_urls(self) -> list[str]:
        """Parsed, whitespace-trimmed feed URL list from HECATE_RUNNER_RSS_FEED_URLS."""
        return [url.strip() for url in self.rss_feed_urls_raw.split(",") if url.strip()]

    @property
    def misp_cursor_file(self) -> Path:
        return self.hecate_workspace / ".misp_cursor_state.json"

    @property
    def misp_org_allowlist(self) -> list[str]:
        """Parsed, whitespace-trimmed org list from HECATE_RUNNER_MISP_ORG_ALLOWLIST."""
        return [name.strip() for name in self.misp_org_allowlist_raw.split(",") if name.strip()]

    @property
    def cti_multi_provider_names(self) -> list[str]:
        """Parsed, whitespace-trimmed sub-provider list from HECATE_RUNNER_CTI_MULTI_PROVIDERS."""
        return [name.strip() for name in self.cti_multi_providers_raw.split(",") if name.strip()]

    @property
    def abuse_ch_cursor_file(self) -> Path:
        return self.hecate_workspace / ".cursors" / "abuse_ch_cursor.json"

    @property
    def certstream_cursor_file(self) -> Path:
        return self.hecate_workspace / ".cursors" / "certstream_cursor.json"

    @property
    def github_poc_cursor_file(self) -> Path:
        return self.hecate_workspace / ".cursors" / "github_poc_cursor.json"

    @property
    def malwarebazaar_cursor_file(self) -> Path:
        return self.hecate_workspace / ".cursors" / "malwarebazaar_cursor.json"

    @property
    def vxunderground_cursor_file(self) -> Path:
        return self.hecate_workspace / ".cursors" / "vxunderground_cursor.json"

    @property
    def certstream_brand_patterns(self) -> list[str]:
        """Parsed, lowercased, whitespace-trimmed brand list from HECATE_RUNNER_CERTSTREAM_BRANDS."""
        return [
            b.strip().lower() for b in self.certstream_brand_patterns_raw.split(",") if b.strip()
        ]

    @property
    def certstream_suspicious_keywords(self) -> list[str]:
        """Parsed, lowercased, whitespace-trimmed suspicious keywords from HECATE_RUNNER_CERTSTREAM_KEYWORDS."""
        return [
            k.strip().lower()
            for k in self.certstream_suspicious_keywords_raw.split(",")
            if k.strip()
        ]

    @property
    def multi_cursor_file(self) -> Path:
        return self.hecate_workspace / ".multi_cti_cursor_state.json"

    @property
    def hunts_root(self) -> Path:
        return self.hecate_workspace / "hunts"

    @property
    def pending_queries_dir(self) -> Path:
        return self.hecate_workspace / ".pending_queries"

    # --- Validators ---------------------------------------------------------

    @field_validator("hecate_workspace")
    @classmethod
    def _expand_workspace(cls, v: Path) -> Path:
        return v.expanduser().resolve()

    def env_for_hecate(self) -> dict[str, str]:
        """Env vars to pass through when subprocessing the hecate-agent CLI.

        LLM keys are included only when explicitly set. hecate calls
        load_dotenv() from the workspace with override=False, so anything
        passed here wins over the workspace's own .env -- omitting the unset
        ones is what lets that file stay authoritative.
        """
        env = {
            "HECATE_WORKSPACE": str(self.hecate_workspace),
            "HECATE_LLM_CALL_LOG": str(self.llm_calls_file),
        }
        if self.hecate_llm_provider:
            env["HECATE_LLM_PROVIDER"] = self.hecate_llm_provider
        if self.hecate_llm_model:
            env["HECATE_LLM_MODEL"] = self.hecate_llm_model
        return env

    def redacted_dict(self) -> dict[str, Any]:
        """Effective settings with secrets masked — safe to paste into an issue."""
        dumped = self.model_dump(mode="json")
        for field_name in self._SENSITIVE_FIELDS:
            if dumped.get(field_name):
                dumped[field_name] = "<redacted>"
        return dumped
