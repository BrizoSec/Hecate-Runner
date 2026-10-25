"""Slack notification hooks and multi-channel routing.

Provides tiered alert dispatching across high-level operational metrics
and specialized threat/source feeds using either a Slack Bot Token (chat:write)
or incoming webhook fallback.

A notification failure must never cost a draft or fail a cycle: every function
catches its own errors and logs a warning instead of raising.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from hecate_runner.config import Settings
from hecate_runner.slack_blocks import (
    build_draft_card,
    build_hunt_completed_card,
    build_ops_metrics_card,
    build_purple_team_card,
    build_threat_intake_card,
)

if TYPE_CHECKING:
    from hecate_runner.cti.base import CTIItem
    from hecate_runner.orchestrator import RunResult

log = logging.getLogger(__name__)


class SlackNotificationRouter:
    """Routes Hecate pipeline events to appropriate Slack channels or webhooks."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self.settings = settings
        self._client = client

    def close(self) -> None:
        if self._client:
            self._client.close()

    @property
    def is_configured(self) -> bool:
        """Return True if either a Slack Bot Token or webhook URL is configured."""
        return bool(self.settings.slack_bot_token or self.settings.slack_webhook_url)

    def resolve_threat_channel(self, evidence_profile: str, source: str = "") -> str:
        """Resolve target Slack channel based on evidence profile or threat source."""
        prof = (evidence_profile or "").lower()
        src = (source or "").lower()

        if prof == "vulnerability_advisory" or src in (
            "first_org",
            "cisa_kev",
            "vulncheck",
            "msrc",
        ):
            return self.settings.slack_channel_exploits

        if prof == "sandbox_execution" or src in (
            "anyrun",
            "triage",
            "malwarebazaar",
            "vxunderground",
        ):
            return self.settings.slack_channel_sandbox

        if prof == "procedural_intrusion" or src in ("opencti", "otx", "dfir_report"):
            return self.settings.slack_channel_apt

        if prof == "cloud_audit_telemetry" or src in ("cloud_threat", "certstream"):
            return self.settings.slack_channel_cloud

        if prof == "network_telemetry" or src in ("censys_c2", "shadowserver", "abuse_ch"):
            return self.settings.slack_channel_c2

        return self.settings.slack_channel_hunts_exec

    def post_message(
        self,
        channel: str,
        text: str,
        *,
        blocks: list[dict[str, Any]] | None = None,
        attachments: list[dict[str, Any]] | None = None,
    ) -> tuple[bool, str]:
        """Post a message to a channel using bot token or webhook fallback."""
        if not self.is_configured:
            return False, "Slack notifications are not configured."

        # Mode 1: Slack Bot Token (chat:write API)
        if self.settings.slack_bot_token:
            url = "https://slack.com/api/chat.postMessage"
            headers = {
                "Authorization": f"Bearer {self.settings.slack_bot_token}",
                "Content-Type": "application/json; charset=utf-8",
            }
            payload: dict[str, Any] = {"channel": channel, "text": text}
            if attachments:
                payload["attachments"] = attachments
            elif blocks:
                payload["blocks"] = blocks

            try:
                if self._client is not None:
                    resp = self._client.post(url, headers=headers, json=payload)
                else:
                    resp = httpx.post(url, headers=headers, json=payload, timeout=10.0)
                resp.raise_for_status()
                data = resp.json()
                if not data.get("ok"):
                    error_msg = str(data.get("error") or "Unknown Slack API error")
                    log.warning(
                        "Slack API postMessage to %s failed: %s; payload text: %s",
                        channel,
                        error_msg,
                        text[:100],
                    )
                    return False, f"Slack API error: {error_msg}"
                return True, "Message posted successfully via Slack Bot API."
            except Exception as exc:
                log.warning("Slack Bot postMessage to %s failed (%s)", channel, exc)
                return False, f"Slack notification failed: {exc}"

        # Mode 2: Slack Webhook Fallback
        if self.settings.slack_webhook_url:
            payload = {"text": text}
            if attachments:
                payload["attachments"] = attachments
            elif blocks:
                payload["blocks"] = blocks

            try:
                if self._client is not None:
                    resp = self._client.post(self.settings.slack_webhook_url, json=payload)
                else:
                    resp = httpx.post(
                        self.settings.slack_webhook_url, json=payload, timeout=10.0
                    )
                resp.raise_for_status()
                return True, "Notification sent successfully."
            except Exception as exc:
                log.warning("Slack webhook notification failed (%s)", exc)
                return False, f"Slack notification failed: {exc}"

        return False, "Slack notifications are not configured."


# --- Pipeline Event Notification Functions ----------------------------------


def notify_draft_created(settings: Settings, result: RunResult) -> None:
    """Post a Slack message for a newly created draft hunt."""
    router = SlackNotificationRouter(settings)
    if not router.is_configured:
        return

    research_context = (
        f"research context {result.research_id}"
        if result.research_id
        else "no research context"
    )
    parked_note = (
        f"\n:information_source: {result.parked_count} item(s) were held back (parked) during intake triage."
        if result.parked_count > 0
        else ""
    )
    text = (
        f":memo: New draft hunt *{result.hunt_id}* ({research_context})\n"
        f"`{result.draft_path}`\n"
        f"Status: `planning` — human review required before execution.{parked_note}"
    )

    attachments = build_draft_card(result)
    router.post_message(settings.slack_channel_hunts_exec, text, attachments=attachments)


def notify_hunt_completed(
    settings: Settings,
    *,
    hunt_id: str,
    topic: str,
    techniques: list[str],
    sigma_count: int,
    pr_url: str = "",
    misp_event_id: str = "",
) -> None:
    """Post an executive summary of a fully validated and completed hunt."""
    router = SlackNotificationRouter(settings)
    if not router.is_configured:
        return

    tech_str = ", ".join(f"`{t}`" for t in techniques[:6]) or "Unspecified"
    pr_part = f"\n*Content PR:* <{pr_url}|View Pull Request>" if pr_url else ""
    misp_part = (
        f"\n*MISP Sync:* Event #{misp_event_id} published" if misp_event_id else ""
    )

    text = (
        f":shield: *Hunt Validated & Published: {hunt_id}*\n"
        f"*Topic:* {topic}\n"
        f"*Techniques Covered:* {tech_str}\n"
        f"*Sigma Detection Rules:* {sigma_count} rules validated"
        f"{pr_part}{misp_part}"
    )

    attachments = build_hunt_completed_card(
        hunt_id=hunt_id,
        topic=topic,
        techniques=techniques,
        sigma_count=sigma_count,
        pr_url=pr_url,
        misp_event_id=misp_event_id,
    )
    router.post_message(settings.slack_channel_hunts_exec, text, attachments=attachments)


def notify_purple_team(
    settings: Settings,
    *,
    hunt_id: str,
    technique: str,
    success: bool,
    telemetry_count: int,
    summary: str,
) -> None:
    """Post purple-team adversary emulation validation outcomes."""
    router = SlackNotificationRouter(settings)
    if not router.is_configured:
        return

    status_icon = ":white_check_mark:" if success else ":warning:"
    status_label = "Detection Validated" if success else "Telemetry / Coverage Gap"

    text = (
        f"{status_icon} *Purple Team Emulation Outcome: {hunt_id}*\n"
        f"*Technique:* `{technique}`\n"
        f"*Validation Status:* `{status_label}`\n"
        f"*Observed Telemetry Logs:* {telemetry_count} events\n"
        f"*Outcome:* {summary}"
    )

    attachments = build_purple_team_card(
        hunt_id=hunt_id,
        technique=technique,
        success=success,
        telemetry_count=telemetry_count,
        summary=summary,
    )
    router.post_message(settings.slack_channel_purple_team, text, attachments=attachments)


def notify_threat_intake(settings: Settings, item: CTIItem) -> None:
    """Route critical incoming threat intelligence to specialized threat feeds."""
    router = SlackNotificationRouter(settings)
    if not router.is_configured:
        return

    profile = str(item.metadata.get("evidence_profile") or "")
    target_channel = router.resolve_threat_channel(profile, item.source)

    text = (
        f":rotating_light: *Threat Intelligence Intake: {item.title}*\n"
        f"*Source:* `{item.source}` | *Evidence Profile:* `{profile}`\n"
        f"*Identifier:* `{item.identifier}`\n"
        f"```{item.content[:280]}...```"
    )

    attachments = build_threat_intake_card(item)
    router.post_message(target_channel, text, attachments=attachments)


def notify_ops_metrics(
    settings: Settings,
    metrics_summary: dict[str, Any],
    channel: str | None = None,
) -> None:
    """Post daily operational and cost metrics digest."""
    router = SlackNotificationRouter(settings)
    if not router.is_configured:
        return

    hunts_done = metrics_summary.get("hunts_completed", 0)
    sigma_total = metrics_summary.get("sigma_rules_produced", 0)
    spend_today = metrics_summary.get("spend_today_usd", 0.0)
    budget = metrics_summary.get("daily_budget_usd", 20.0)
    active_sources = metrics_summary.get("active_sources", [])

    sources_str = ", ".join(f"`{s}`" for s in active_sources) or "None"

    text = (
        f":bar_chart: *Hecate Daily Autonomous Ops & Spend Digest*\n"
        f"*Hunts Completed (24h):* `{hunts_done}`\n"
        f"*Sigma Detection Rules Produced:* `{sigma_total}`\n"
        f"*Today's Spend / Budget:* `${spend_today:.2f} / ${budget:.2f}`\n"
        f"*Active Threat Feeds:* {sources_str}"
    )

    target_channel = channel or settings.slack_channel_ops_metrics
    attachments = build_ops_metrics_card(metrics_summary)
    router.post_message(target_channel, text, attachments=attachments)


def send_test_notification(
    settings: Settings, channel: str | None = None
) -> tuple[bool, str]:
    """Send a test message to verify Slack connectivity. Returns (success, message)."""
    router = SlackNotificationRouter(settings)
    if not router.is_configured:
        return (
            False,
            "HECATE_RUNNER_SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN is not configured.",
        )

    target_channel = channel or settings.slack_channel_hunts_exec
    text = (
        ":white_check_mark: *Hecate Pipeline Slack Connectivity Test*\n"
        f"Verified communication from Hecate-Runner to `{target_channel}`."
    )
    return router.post_message(target_channel, text)


def send_test_all_channels(settings: Settings) -> dict[str, tuple[bool, str]]:
    """Test connectivity across all 8 configured Slack channels."""
    channels = [
        settings.slack_channel_ops_metrics,
        settings.slack_channel_hunts_exec,
        settings.slack_channel_purple_team,
        settings.slack_channel_exploits,
        settings.slack_channel_sandbox,
        settings.slack_channel_apt,
        settings.slack_channel_cloud,
        settings.slack_channel_c2,
    ]

    results: dict[str, tuple[bool, str]] = {}
    for ch in channels:
        results[ch] = send_test_notification(settings, channel=ch)
    return results
