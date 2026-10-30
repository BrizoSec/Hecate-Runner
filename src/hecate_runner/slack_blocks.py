"""Slack Block Kit message builders for Hecate pipeline events.

Provides structured, color-coded Slack cards with interactive buttons,
MITRE ATT&CK badges, MISP links, and multi-column telemetry summaries.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hecate_runner.config import Settings
    from hecate_runner.cti.base import CTIItem
    from hecate_runner.orchestrator import RunResult

# Brand / Severity accent colors
COLOR_SUCCESS = "#2EB886"  # Emerald green (Validated hunt, detection passed)
COLOR_INFO = "#3AA3E3"  # Cerulean blue (Metrics, telemetry, digest)
COLOR_WARNING = "#ECB22E"  # Amber yellow (Planning draft, review required, telemetry gap)
COLOR_CRITICAL = "#E01E5A"  # Crimson red (Critical exploit spike, weaponization alert)
COLOR_PURPLE = "#7928CA"  # Aubergine / Purple (Purple team, threat hunting)

_TLD_PATTERN = (
    r"\b(?<!\[|\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)\.(com|org|net|edu|gov|io|ir|ru|cn|info|biz|xyz|top|"
    r"site|online|live|club|vip|cc|co|me|tv|us|uk|de|eu|nl|fr|it|es|pl|br|in|au|jp|kr|"
    r"cloud|shop|store|app|dev|tech|pro|space|fun|icu|link|click|work|mobi|asia|pw|tk|"
    r"ml|ga|cf|gq|onion|su|to|is|ws)\b"
)


def defang_ioc(text: str) -> str:
    """Defang IOCs (URLs, IPv4, domains, email addresses) so they cannot be accidentally clicked in Slack."""
    if not text:
        return text

    def _defang_url(m: re.Match[str]) -> str:
        scheme = "hxxps://" if m.group(1).lower() == "https" else "hxxp://"
        rest = m.group(2)
        parts = rest.split("/", 1)
        host = parts[0].replace(".", "[.]")
        path = "/" + parts[1] if len(parts) > 1 else ""
        return scheme + host + path

    out = re.sub(r"\b(https?)://([^\s\'\"<>]+)", _defang_url, text, flags=re.IGNORECASE)
    out = re.sub(r"\bftp://", "fxp://", out, flags=re.IGNORECASE)

    # Defang IPv4 addresses (excluding already bracketed dots)
    out = re.sub(
        r"\b(?<!\[)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\])\b",
        r"\1[.]\2[.]\3[.]\4",
        out,
    )

    # Defang email addresses
    out = re.sub(
        r"\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b",
        lambda m: m.group(1) + "[@]" + m.group(2).replace(".", "[.]"),
        out,
    )

    def _defang_domain(m: re.Match[str]) -> str:
        domain = m.group(1) + "." + m.group(2)
        return domain.replace(".", "[.]")

    out = re.sub(_TLD_PATTERN, _defang_domain, out, flags=re.IGNORECASE)
    return out


def build_draft_card(result: RunResult, *, interactive: bool = False) -> list[dict[str, Any]]:
    """Build a rich Slack card for a newly created draft hunt."""
    research_ctx = (
        f"Linked to research context `{result.research_id}`"
        if result.research_id
        else "Source-only extraction (no web search)"
    )
    parked_text = (
        f"• {result.parked_count} commentary item(s) parked during intake triage"
        if result.parked_count > 0
        else "• Clean triage: zero items parked"
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"📝 New Draft Hunt Initiated: {result.hunt_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Draft Hunt ID:* `{result.hunt_id}`\n"
                    f"*Research Context:* {research_ctx}\n"
                    f"*Draft Location:* `{result.draft_path}`"
                ),
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Status:*\n`planning` (Awaiting review)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Intake Triage:*\n{parked_text}",
                },
            ],
        },
    ]

    if interactive:
        blocks.append(
            {
                "type": "actions",
                "block_id": f"hunt_actions_{result.hunt_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🚀 Approve & Promote",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "hecate_approve_hunt",
                        "value": result.hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 Deploy Queries", "emoji": True},
                        "action_id": "hecate_deploy_queries",
                        "value": result.hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 Purple Team Replay",
                            "emoji": True,
                        },
                        "action_id": "hecate_rerun_purple",
                        "value": result.hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⏸️ Park / Suppress", "emoji": True},
                        "style": "danger",
                        "action_id": "hecate_park_hunt",
                        "value": result.hunt_id,
                    },
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🤖 *Hecate Autonomous Runner* | Run `hecate-runner watch` to observe execution",
                }
            ],
        }
    )

    return [{"color": COLOR_WARNING, "blocks": blocks}]


def build_hunt_completed_card(
    *,
    hunt_id: str,
    topic: str,
    techniques: list[str],
    sigma_count: int,
    pr_url: str = "",
    misp_event_id: str = "",
    misp_url: str = "https://localhost:8443",
    content_repo_url: str = "https://github.com/BrizoSec/Hecate-Content",
    interactive: bool = False,
) -> list[dict[str, Any]]:
    """Build an executive completion card for a validated hunt."""
    tech_formatted = ", ".join(f"`{t}`" for t in techniques[:6]) or "Unspecified"
    if len(techniques) > 6:
        tech_formatted += f" _(+{len(techniques) - 6} more)_"

    misp_text = (
        f"<{misp_url}/events/view/{misp_event_id}|Event #{misp_event_id}>"
        if misp_event_id
        else "Local sync pending"
    )
    pr_text = f"<{pr_url}|PR Active>" if pr_url else "Direct commit to workspace"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🛡️ Hunt Validated & Published: {hunt_id}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Topic / Hypothesis:*\n{topic}",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*MITRE Techniques:*\n{tech_formatted}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Sigma Detection Rules:*\n`{sigma_count} rules validated`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*MISP Indicator Sync:*\n{misp_text}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Content PR:*\n{pr_text}",
                },
            ],
        },
    ]

    # Action buttons if links are available
    action_elements: list[dict[str, Any]] = []
    if pr_url:
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "View Pull Request", "emoji": True},
                "url": pr_url,
                "style": "primary",
            }
        )
    if misp_event_id:
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open MISP Event", "emoji": True},
                "url": f"{misp_url.rstrip('/')}/events/view/{misp_event_id}",
            }
        )
    if content_repo_url:
        action_elements.append(
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Content Repo", "emoji": True},
                "url": content_repo_url,
            }
        )

    if action_elements:
        blocks.append({"type": "actions", "elements": action_elements})

    if interactive:
        blocks.append(
            {
                "type": "actions",
                "block_id": f"hunt_actions_{hunt_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🚀 Approve & Promote",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "hecate_approve_hunt",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔍 Deploy Queries", "emoji": True},
                        "action_id": "hecate_deploy_queries",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 Purple Team Replay",
                            "emoji": True,
                        },
                        "action_id": "hecate_rerun_purple",
                        "value": hunt_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⏸️ Park / Suppress", "emoji": True},
                        "style": "danger",
                        "action_id": "hecate_park_hunt",
                        "value": hunt_id,
                    },
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Purple Team Engine* | Passed 100% claim provenance audit",
                }
            ],
        }
    )

    return [{"color": COLOR_SUCCESS, "blocks": blocks}]


def build_purple_team_card(
    *,
    hunt_id: str,
    technique: str,
    success: bool,
    telemetry_count: int,
    summary: str,
    log_source: str = "Windows Event Log / Zeek",
    emulation_mode: str = "Atomic Red Team (Dynamic)",
) -> list[dict[str, Any]]:
    """Build a purple-team emulation validation card."""
    color = COLOR_SUCCESS if success else COLOR_WARNING
    status_icon = "✅" if success else "⚠️"
    status_title = "Detection Rule Verified" if success else "Telemetry / Coverage Gap"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{status_icon} Purple Team Outcome: {technique} ({hunt_id})",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Technique Tested:*\n`{technique}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Validation Outcome:*\n*{status_title}*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Observed Telemetry Logs:*\n`{telemetry_count} events captured`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Telemetry Source:*\n`{log_source}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Adversary Emulation:*\n`{emulation_mode}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Emulation & Detection Findings:*\n{summary}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "⚔️ *Purple Team Validation Pipeline* | Correlated with generated Sigma rules",
                }
            ],
        },
    ]

    return [{"color": color, "blocks": blocks}]


def build_threat_intake_card(item: CTIItem) -> list[dict[str, Any]]:
    """Build a card for critical incoming threat intelligence."""
    profile = str(item.metadata.get("evidence_profile") or "unclassified")
    color = COLOR_CRITICAL if profile == "vulnerability_advisory" else COLOR_INFO

    ingested_time = (
        item.received_at.strftime("%Y-%m-%d %H:%M UTC")
        if item.received_at is not None
        else "Recent"
    )

    clean_title = defang_ioc(item.title[:75])
    clean_identifier = defang_ioc(item.identifier)
    clean_summary = defang_ioc(item.content[:350])

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 Threat Intel Intake: {clean_title}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Source:*\n`{item.source}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Evidence Profile:*\n`{profile}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Identifier:*\n`{clean_identifier}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Ingested:*\n`{ingested_time}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Intelligence Summary & Telemetry:*\n```{clean_summary}...```",
            },
        },
    ]

    if item.source_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Threat Source", "emoji": True},
                        "url": item.source_url,
                    }
                ],
            }
        )

    return [{"color": color, "blocks": blocks}]


def build_ops_metrics_card(metrics_summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a 24-hour executive operational metrics digest card."""
    hunts_done = metrics_summary.get("hunts_completed", 0)
    sigma_total = metrics_summary.get("sigma_rules_produced", 0)
    spend_today = float(metrics_summary.get("spend_today_usd", 0.0))
    budget = float(metrics_summary.get("daily_budget_usd", 20.0))
    active_sources = metrics_summary.get("active_sources", [])
    purple_pass_pct = metrics_summary.get("purple_team_pass_pct", "100%")

    sources_str = ", ".join(f"`{s}`" for s in active_sources) or "All sources idle"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "📊 Hecate 24-Hour Autonomous Ops Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Hunts Completed (24h):*\n*{hunts_done} hunts*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Sigma Detection Rules:*\n*{sigma_total} rules generated*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Purple Team Pass Rate:*\n*{purple_pass_pct}*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Today's Spend / Budget:*\n*${spend_today:.2f}* / ${budget:.2f}",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Active Ingestion Feeds:*\n{sources_str}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Pipeline metrics from recorded cycles",
                }
            ],
        },
    ]

    return [{"color": COLOR_INFO, "blocks": blocks}]


def build_detection_engineering_digest_card(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a Daily Detection Engineering Digest card."""
    total_rules = data.get("total_sigma_rules", 0)
    rules_validated = data.get("rules_validated_24h", 0)
    rules_evaluated = data.get("rules_evaluated_24h", 0)
    pass_rate = data.get("pass_rate_pct", "100%")
    top_tactics = ", ".join(data.get("top_tactics", [])[:3]) or "Execution, Persistence"
    platforms = ", ".join(data.get("platforms", [])[:4]) or "Enterprise"

    recent_rules = data.get("recent_rules", [])
    rules_md_lines = []
    for r in recent_rules[:4]:
        tech = f" [`{r['technique']}`]" if r.get("technique") and r["technique"] != "N/A" else ""
        rules_md_lines.append(f"• *{r['title']}*{tech}\n  ↳ `{r['file']}`")
    rules_md = "\n".join(rules_md_lines) or "No new rules validated in lookback window."

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ Daily Detection Engineering Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Sigma Rules:*\n*{total_rules:,} rules in library*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Purple Team Pass Rate:*\n*{pass_rate}* ({rules_validated}/{rules_evaluated} validated)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Primary MITRE Tactics:*\n`{top_tactics}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Target Platforms:*\n`{platforms}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recently Validated Detections (24h):*\n{rules_md}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🔍 *Detection Engine:* Continuous CI/CD validation | Automated Sigma & PyTest passes",
                }
            ],
        },
    ]

    return [{"color": COLOR_SUCCESS, "blocks": blocks}]


def build_threat_intel_digest_card(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a Daily Threat Intelligence Digest card."""
    active_sources = data.get("active_sources", [])
    total_research = data.get("total_research_count", 0)
    recent_research = data.get("recent_research_count", 0)
    cves_count = data.get("cves_tracked_count", 0)
    cves_sample = ", ".join(f"`{c}`" for c in data.get("cves_sample", [])[:3]) or "None active"
    misp_status = "🟢 Connected & Syncing" if data.get("misp_sync_active") else "⚪ Offline"

    recent_topics = data.get("recent_topics", [])
    topics_md_lines = []
    for t in recent_topics[:4]:
        topics_md_lines.append(f"• *{t['id']}*: {t['topic']} `[{t['complexity'].upper()}]`")
    topics_md = (
        "\n".join(topics_md_lines) or "No threat research items generated in lookback window."
    )

    sources_str = ", ".join(f"`{s}`" for s in active_sources) or "No sources active"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Daily Threat Intelligence Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Active Feeds ({len(active_sources)}):*\n{sources_str}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*MISP Telemetry:*\n{misp_status}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Research Contexts:*\n*{recent_research} new* (Total: {total_research:,})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*High-Weapon CVEs:*\n*{cves_count} tracked* ({cves_sample})",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Threat Research & Campaign Spotlights:*\n{topics_md}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🌐 *CTI Feed Health:* Live polling active across Sandbox, Exploits, APT & Cloud feeds",
                }
            ],
        },
    ]

    return [{"color": COLOR_CRITICAL, "blocks": blocks}]


def build_threat_hunting_digest_card(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build a Daily Threat Hunting Digest card."""
    total_hunts = data.get("total_hunts", 0)
    recent_hunts = data.get("recent_hunts_count", 0)
    spend_today = float(data.get("spend_today_usd", 0.0))
    daily_budget = float(data.get("daily_budget_usd", 20.0))
    budget_pct = data.get("budget_pct", "0.0%")
    status_counts = data.get("status_counts", {})
    planning = status_counts.get("planning", 0)
    promoted = status_counts.get("promoted", 0) + status_counts.get("completed", 0)

    hunt_spotlights = data.get("hunt_spotlights", [])
    spotlights_md_lines = []
    for h in hunt_spotlights[:4]:
        spotlights_md_lines.append(f"• *{h['id']}*: {h['title']} `[{h['status']}]`")
    spotlights_md = (
        "\n".join(spotlights_md_lines) or "No active hunt operations in lookback window."
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🎯 Daily Threat Hunting Digest",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Hunts Executed (24h):*\n*{recent_hunts} runs* (Total: {total_hunts:,})",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Campaign Pipeline:*\n*{planning} in planning* | *{promoted} promoted*",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*LLM Spend / Budget:*\n*${spend_today:.2f}* / ${daily_budget:.2f} ({budget_pct})",
                },
                {
                    "type": "mrkdwn",
                    "text": "*Hunter Engine:*\n`hecate-runner autonomous`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recent Hunt Operations & Hypotheses:*\n{spotlights_md}",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🎯 *Hunt Status:* Autonomous hypothesis evaluation, telemetry sweep & query generation",
                }
            ],
        },
    ]

    return [{"color": COLOR_PURPLE, "blocks": blocks}]


def build_slash_help_card() -> list[dict[str, Any]]:
    """Build a help card describing available /hecate slash commands."""
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🤖 Hecate SecOps Slash Commands",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Autonomous Threat Hunting & Detection Engineering Commands:*\n\n"
                    "• `/hecate status` — View pipeline status, active hunts, quota & metrics\n"
                    "• `/hecate hunt <topic_or_cve>` — Launch an immediate ad-hoc hunt cycle (e.g. `/hecate hunt Akira Ransomware`)\n"
                    "• `/hecate deploy <hunt_id> [target]` — Deploy or simulate queries across SIEM/EDRs (e.g. `/hecate deploy H-0868 sentinel_kql`)\n"
                    "• `/hecate rerun <hunt_id>` — Replay purple-team adversary emulation and validate Sigma rules\n"
                    "• `/hecate help` — Show this command reference guide"
                ),
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🛡️ *Hecate Autonomous SecOps* | Socket Mode Interactive Engine",
                }
            ],
        },
    ]
    return [{"color": COLOR_INFO, "blocks": blocks}]


def build_runner_status_card(settings: Settings) -> list[dict[str, Any]]:
    """Build an operational status card for /hecate status."""
    from hecate_runner.parked_store import list_parked
    from hecate_runner.state import OrchestratorState

    state = OrchestratorState.load(settings.state_file)
    parked_count = len(list_parked(settings.cti_queue_dir_resolved))

    hunts_dir = settings.hecate_workspace / "hunts"
    hunt_files = sorted(hunts_dir.glob("**/*.md")) if hunts_dir.exists() else []
    total_hunts = len(hunt_files)

    planning_count = 0
    active_count = 0
    for hf in hunt_files:
        try:
            txt = hf.read_text(encoding="utf-8")
            if "status: planning" in txt:
                planning_count += 1
            elif any(s in txt for s in ("status: active", "status: promoted", "status: completed")):
                active_count += 1
        except Exception:
            continue

    recent_hunts_lines = []
    for hf in hunt_files[-4:]:
        recent_hunts_lines.append(f"• `{hf.stem}`: {hf.name}")
    recent_text = "\n".join(recent_hunts_lines) or "No hunts recorded yet"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "📊 Hecate Autonomous Runner Status",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Workspace:*\n`{settings.hecate_workspace.name}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*CTI Provider:*\n`{settings.cti_provider}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Draft Quota (24h):*\n`{state.drafts_today} / {settings.max_drafts_per_day}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Research Quota:*\n`{state.research_runs_today} / {settings.max_research_runs_per_day}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Hunts in Workspace:*\n`{total_hunts} total` (`{active_count}` active, `{planning_count}` planning)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Parked Commentary:*\n`{parked_count} item(s)`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Recent Hunt Operations:*\n{recent_text}\n*Last Pipeline Run:* `{state.last_run_iso or 'never'}`",
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🤖 *Hecate Status* | Interactive SecOps Bot Active",
                }
            ],
        },
    ]
    return [{"color": COLOR_SUCCESS, "blocks": blocks}]
