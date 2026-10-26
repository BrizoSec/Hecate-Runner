"""Offline simulation harness and interactive terminal for Hecate Slack Bot operations.

Allows offline verification of:
- Interactive Block Kit actions (approve, deploy, replay, park)
- Slash commands (/hecate status, /hecate hunt, /hecate deploy, /hecate rerun, /hecate help)
- Conversational Sigma rule tuning instructions ("H-0700: Exclude svchost.exe")
without requiring live Slack Socket Mode credentials or network connectivity.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from hecate_runner.config import Settings
from hecate_runner.rule_tuner import RuleTuner
from hecate_runner.slack_blocks import build_runner_status_card, build_slash_help_card
from hecate_runner.slack_bot import (
    deploy_queries_for_hunt,
    execute_adhoc_hunt,
    park_hunt,
    promote_hunt,
    replay_hunt_purple_team,
)

log = logging.getLogger(__name__)


class SlackBotSimulator:
    """Offline simulation engine for Hecate Slack interactions."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self.workspace = self.settings.hecate_workspace
        self.tuner = RuleTuner(self.workspace)

    def simulate_action(self, action_id: str, value: str, user: str = "analyst") -> dict[str, Any]:
        """Simulate an interactive button click (e.g. approve, deploy, replay, park)."""
        hunt_id = value.strip().upper()

        if action_id == "hecate_approve_hunt":
            res = promote_hunt(self.workspace, hunt_id)
            if res.get("ok"):
                already_str = " (was already active)" if res.get("already_promoted") else ""
                msg = (
                    f"🚀 *Hunt `{hunt_id}` Approved & Promoted!*{already_str}\n"
                    f"• *Reviewer:* <@{user}>\n"
                    f"• *Status:* `active`\n"
                    f"• *Workspace File:* `{res.get('path')}`\n"
                    f"• *Provenance Audit:* Verified mathematically grounded."
                )
            else:
                msg = f"❌ *Failed to promote `{hunt_id}`:* {res.get('error')}"
            return {"ok": bool(res.get("ok")), "action": action_id, "message": msg, "data": res}

        elif action_id == "hecate_deploy_queries":
            is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
            mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live API Push"
            deployments = deploy_queries_for_hunt(self.workspace, hunt_id, dry_run=is_dry_run)
            if not deployments:
                msg = f"⚠️ *No queries found for `{hunt_id}`* under `queries/{hunt_id}`."
                return {"ok": False, "action": action_id, "message": msg, "deployments": []}

            rows = []
            for d in deployments:
                icon = "✅" if d.get("ok") else "❌"
                tgt = d.get("target")
                st = d.get("status")
                rem_id = f" (`{d.get('remote_id')}`)" if d.get("remote_id") else ""
                rows.append(f"{icon} *{tgt}:* `{st}`{rem_id}")

            rows_text = "\n".join(rows)
            msg = (
                f"🔍 *SIEM & EDR Query Deployment for `{hunt_id}`*\n"
                f"*Mode:* `{mode_str}` | *Reviewer:* <@{user}>\n\n"
                f"{rows_text}"
            )
            return {
                "ok": True,
                "action": action_id,
                "message": msg,
                "deployments": deployments,
            }

        elif action_id == "hecate_purple_replay":
            res = replay_hunt_purple_team(self.workspace, hunt_id)
            if res.get("ok"):
                msg = (
                    f"🧪 *Purple Team Replay for `{hunt_id}` Completed*\n"
                    f"• *Reviewer:* <@{user}>\n"
                    f"• *Rules Tested:* {res.get('total_rules')}\n"
                    f"• *Rules Validated:* {res.get('passed_rules')}\n"
                    f"• *Detection Fidelity:* {res.get('fidelity')}\n"
                    f"• *Sandbox Telemetry:* {res.get('sample_events_count')} events evaluated"
                )
            else:
                msg = f"❌ *Purple Team Replay failed for `{hunt_id}`:* {res.get('error')}"
            return {"ok": bool(res.get("ok")), "action": action_id, "message": msg, "data": res}

        elif action_id == "hecate_park_hunt":
            res = park_hunt(self.workspace, hunt_id)
            if res.get("ok"):
                msg = (
                    f"⏸️ *Hunt `{hunt_id}` Parked / Suppressed*\n"
                    f"• *Reviewer:* <@{user}>\n"
                    f"• *Status:* `suppressed`\n"
                    f"• Marked as commentary / un-actionable intelligence."
                )
            else:
                msg = f"❌ *Failed to park `{hunt_id}`:* {res.get('error')}"
            return {"ok": bool(res.get("ok")), "action": action_id, "message": msg, "data": res}

        return {
            "ok": False,
            "action": action_id,
            "message": f"Unknown action ID: '{action_id}'",
        }

    def simulate_command(
        self, command_line: str, user: str = "analyst", channel: str = "C_SIM"
    ) -> dict[str, Any]:
        """Simulate a Slack slash command (e.g. '/hecate status' or '/hecate hunt CVE-2024-38077')."""
        clean = command_line.strip()
        if clean.startswith("/hecate"):
            clean = clean[len("/hecate") :].strip()
        elif clean.startswith("hecate"):
            clean = clean[len("hecate") :].strip()

        tokens = clean.split()
        subcmd = tokens[0].lower() if tokens else "help"

        if subcmd in {"help", "-h", "--help"}:
            card = build_slash_help_card()
            return {
                "ok": True,
                "command": "help",
                "attachments": card,
                "text": "🤖 Hecate SecOps Slash Commands Reference",
            }

        if subcmd == "status":
            card = build_runner_status_card(self.settings)
            return {
                "ok": True,
                "command": "status",
                "attachments": card,
                "text": "📊 Hecate Autonomous SecOps Runner Status",
            }

        if subcmd == "deploy":
            if len(tokens) < 2:
                msg = (
                    "⚠️ *Usage:* `/hecate deploy <hunt_id> [target]`\n"
                    "• Example: `/hecate deploy H-0868`\n"
                    "• Example: `/hecate deploy H-0868 sentinel_kql`"
                )
                return {"ok": False, "command": "deploy", "text": msg}

            hunt_id = tokens[1].upper()
            target = tokens[2].lower() if len(tokens) > 2 else None
            is_dry_run = getattr(self.settings, "siem_deploy_dry_run", True)
            mode_str = "Simulated (Dry-Run)" if is_dry_run else "Live API Push"

            deployments = deploy_queries_for_hunt(
                self.workspace,
                hunt_id,
                dry_run=is_dry_run,
                target=target,
            )
            if not deployments:
                msg = f"⚠️ *No queries found for `{hunt_id}`* under `queries/{hunt_id}`."
                return {"ok": False, "command": "deploy", "text": msg, "deployments": []}

            rows = []
            for d in deployments:
                icon = "✅" if d.get("ok") else "❌"
                tgt = d.get("target")
                st = d.get("status")
                rem_id = f" (`{d.get('remote_id')}`)" if d.get("remote_id") else ""
                rows.append(f"{icon} *{tgt}:* `{st}`{rem_id}")

            rows_text = "\n".join(rows)
            msg = (
                f"🔍 *SIEM & EDR Query Deployment for `{hunt_id}`*\n"
                f"*Mode:* `{mode_str}` | *Initiated by:* <@{user}>\n\n"
                f"{rows_text}"
            )
            return {"ok": True, "command": "deploy", "text": msg, "deployments": deployments}

        if subcmd == "rerun":
            if len(tokens) < 2:
                return {
                    "ok": False,
                    "command": "rerun",
                    "text": "⚠️ *Usage:* `/hecate rerun <hunt_id>` (e.g. `/hecate rerun H-0868`)",
                }

            hunt_id = tokens[1].upper()
            res = replay_hunt_purple_team(self.workspace, hunt_id)
            if res.get("ok"):
                msg = (
                    f"🧪 *Purple Team Replay for `{hunt_id}` Completed*\n"
                    f"• *Requested by:* <@{user}>\n"
                    f"• *Rules Tested:* {res.get('total_rules')}\n"
                    f"• *Rules Validated:* {res.get('passed_rules')}\n"
                    f"• *Detection Fidelity:* {res.get('fidelity')}\n"
                    f"• *Sandbox Telemetry:* {res.get('sample_events_count')} events evaluated"
                )
            else:
                msg = f"❌ *Purple Team Replay failed for `{hunt_id}`:* {res.get('error')}"
            return {"ok": bool(res.get("ok")), "command": "rerun", "text": msg, "data": res}

        if subcmd == "hunt":
            if len(tokens) < 2:
                msg = (
                    "⚠️ *Usage:* `/hecate hunt <topic_or_cve>`\n"
                    "• Example: `/hecate hunt Akira Ransomware`\n"
                    "• Example: `/hecate hunt CVE-2024-38077`"
                )
                return {"ok": False, "command": "hunt", "text": msg}

            topic = " ".join(tokens[1:])
            try:
                res = execute_adhoc_hunt(self.settings, topic=topic)
                if getattr(res, "ok", False) and getattr(res, "hunt_id", None):
                    finish_msg = (
                        f"✅ *Ad-hoc Hunt Completed: `{res.hunt_id}`*\n"
                        f"• *Topic:* {topic}\n"
                        f"• *Draft Path:* `{res.draft_path}`\n"
                        f"• *Research ID:* `{res.research_id or 'none'}`"
                    )
                    return {"ok": True, "command": "hunt", "text": finish_msg, "data": res}
                else:
                    outcome = getattr(res, "outcome", "error")
                    detail = getattr(res, "detail", "")
                    finish_msg = f"⚠️ *Ad-hoc Hunt finished with status `{outcome}`:* {detail}"
                    return {"ok": False, "command": "hunt", "text": finish_msg, "data": res}
            except Exception as h_err:
                finish_msg = f"❌ *Ad-hoc Hunt failed for `{topic}`:* {h_err}"
                return {"ok": False, "command": "hunt", "text": finish_msg, "error": str(h_err)}

        return {
            "ok": False,
            "command": subcmd,
            "text": f"❓ Unknown command `/hecate {subcmd}`. Type `/hecate help` for available commands.",
        }

    def simulate_thread_tuning(
        self, hunt_id: str, instruction: str, user: str = "analyst"
    ) -> dict[str, Any]:
        """Simulate conversational rule tuning in a thread."""
        res = self.tuner.tune_hunt_rule(hunt_id, instruction)
        if res.ok:
            targets_str = ", ".join(f"`{t}`" for t in res.transpiled_targets) or "None"
            msg = (
                f"🛠️ *Sigma Rule Tuned & Re-Transpiled for `{hunt_id}`*\n"
                f"• *Analyst Instruction:* _{instruction}_\n"
                f"• *Action Taken:* {res.action_summary}\n"
                f"• *Updated Telemetry Targets:* {targets_str}\n\n"
                f"```diff\n{res.diff}\n```"
            )
        else:
            msg = (
                f"⚠️ *Rule Tuning Note for `{hunt_id}`:* {res.error}\n"
                f"_Try instructions like 'Exclude svchost.exe', 'Filter out CommandLine /update', or 'Add Image pwsh.exe'._"
            )

        return {
            "ok": res.ok,
            "hunt_id": hunt_id,
            "summary": res.action_summary,
            "diff": res.diff,
            "targets": res.transpiled_targets,
            "message": msg,
            "error": res.error,
        }

    def execute_sim_line(self, raw_line: str) -> str:
        """Parse and execute a simulation command line and return formatted output."""
        line = raw_line.strip()
        if not line:
            return ""

        # Check for /hecate slash command
        if line.startswith(("/hecate", "hecate")):
            res = self.simulate_command(line)
            if "attachments" in res:
                # Format card blocks into readable text
                blocks = res["attachments"][0].get("blocks", [])
                lines = []
                for b in blocks:
                    t = b.get("text", {})
                    if isinstance(t, dict):
                        lines.append(t.get("text", ""))
                    elif isinstance(t, str):
                        lines.append(t)
                return "\n".join(lines) if lines else res.get("text", "")
            return str(res.get("text", ""))

        # Check for action commands: approve, deploy, replay, park
        m_act = re.match(
            r"^(approve|deploy|replay|rerun|park)\s+([Hh]-\d{4})(?:\s+([a-zA-Z0-9_]+))?",
            line,
            re.IGNORECASE,
        )
        if m_act:
            verb = m_act.group(1).lower()
            hid = m_act.group(2).upper()
            extra = m_act.group(3)
            if verb == "approve":
                return str(self.simulate_action("hecate_approve_hunt", hid)["message"])
            elif verb == "deploy":
                if extra:
                    return str(self.simulate_command(f"deploy {hid} {extra}")["text"])
                return str(self.simulate_action("hecate_deploy_queries", hid)["message"])
            elif verb in {"replay", "rerun"}:
                return str(self.simulate_action("hecate_purple_replay", hid)["message"])
            elif verb == "park":
                return str(self.simulate_action("hecate_park_hunt", hid)["message"])

        # Check for tuning commands: "tune <hunt_id> <instruction>" or "<hunt_id>: <instruction>"
        m_tune = re.match(r"^(?:tune\s+)?([Hh]-\d{4})[:\s]+(.*)$", line, re.IGNORECASE)
        if m_tune:
            hid = m_tune.group(1).upper()
            inst = m_tune.group(2).strip()
            return str(self.simulate_thread_tuning(hid, inst)["message"])

        if line.lower() in {"help", "?"}:
            return (
                "🤖 *Hecate Slack Bot Offline Simulation Harness*\n\n"
                "Available commands:\n"
                "• `/hecate status`                       - View runner status card\n"
                "• `/hecate hunt <cve_or_topic>`          - Run ad-hoc autonomous hunt\n"
                "• `/hecate deploy <hunt_id> [target]`    - Deploy queries to SIEM/EDR\n"
                "• `/hecate rerun <hunt_id>`              - Replay purple team adversary emulation\n"
                "• `/hecate help`                         - Show slash command reference\n"
                "• `approve <hunt_id>`                    - Simulate [🚀 Approve & Promote] button\n"
                "• `deploy <hunt_id> [target]`            - Simulate [🔍 Deploy Queries] button\n"
                "• `replay <hunt_id>`                     - Simulate [🧪 Purple Team Replay] button\n"
                "• `park <hunt_id>`                       - Simulate [⏸️ Park / Suppress] button\n"
                "• `tune <hunt_id> <instruction>`         - Conversational Sigma rule tuning\n"
                "• `exit` or `quit`                       - Exit simulation harness"
            )

        return f"❓ Unknown simulation command: '{line}'. Type 'help' for available commands."

    def run_repl(self, console: Console | None = None) -> None:
        """Run an interactive offline simulation terminal REPL."""
        con = console or Console()
        con.print(
            Panel(
                "[bold cyan]Hecate Slack Bot — Offline Interactive Simulation Harness[/bold cyan]\n"
                "[dim]Test Block Kit buttons, /hecate commands, and conversational rule tuning offline.[/dim]\n"
                "Type [bold]help[/bold] for instructions, or [bold]exit[/bold] to quit.",
                title="🛡️ Hecate HITL Sim",
                border_style="cyan",
            )
        )

        while True:
            try:
                line = con.input("[bold green]hecate-slack-sim > [/bold green]").strip()
            except (KeyboardInterrupt, EOFError):
                con.print("\n[dim]Exiting Slack Bot simulation harness.[/dim]")
                break

            if not line:
                continue

            if line.lower() in {"exit", "quit", ":q"}:
                con.print("[dim]Exiting Slack Bot simulation harness.[/dim]")
                break

            output = self.execute_sim_line(line)
            if "```diff" in output:
                parts = output.split("```diff")
                prefix = parts[0].strip()
                diff_and_suffix = parts[1].split("```")
                diff_body = diff_and_suffix[0].strip()
                con.print(prefix)
                con.print(Syntax(diff_body, "diff", theme="monokai", line_numbers=True))
                if len(diff_and_suffix) > 1 and diff_and_suffix[1].strip():
                    con.print(diff_and_suffix[1].strip())
            else:
                con.print(output)
            con.print()
