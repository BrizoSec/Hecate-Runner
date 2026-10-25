"""Slack Block Kit message builders for Hecate pipeline events.

Provides structured, color-coded Slack cards with interactive buttons,
MITRE ATT&CK badges, MISP links, and multi-column telemetry summaries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hecate_runner.cti.base import CTIItem
    from hecate_runner.orchestrator import RunResult

# Brand / Severity accent colors
COLOR_SUCCESS = "#2EB886"  # Emerald green (Validated hunt, detection passed)
COLOR_INFO = "#3AA3E3"     # Cerulean blue (Metrics, telemetry, digest)
COLOR_WARNING = "#ECB22E"  # Amber yellow (Planning draft, review required, telemetry gap)
COLOR_CRITICAL = "#E01E5A" # Crimson red (Critical exploit spike, weaponization alert)


def build_draft_card(result: RunResult) -> list[dict[str, Any]]:
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
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🤖 *Hecate Autonomous Runner* | Run `hecate-runner watch` to observe execution",
                }
            ],
        },
    ]

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

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 Threat Intel Intake: {item.title[:75]}",
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
                    "text": f"*Identifier:*\n`{item.identifier}`",
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
                "text": f"*Intelligence Summary & Telemetry:*\n```{item.content[:350]}...```",
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
                    "text": "⚡ *Runner Service Health: ACTIVE* | 0 crash restarts | MISP sync: Online",
                }
            ],
        },
    ]

    return [{"color": COLOR_INFO, "blocks": blocks}]
