"""Typer-based CLI entry point.

Commands:
    sec7669 run           Execute one orchestrator cycle
    sec7669 status        Print state, quota, config summary
    sec7669 config        Dump effective config (redacts secrets)
    sec7669 doctor        Sanity-check the deployment
    sec7669 otx-poll      Route one high-signal OTX pulse into the CTI queue
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from dotenv import dotenv_values
from rich.console import Console
from rich.table import Table

from sec7669 import __version__
from sec7669.config import Settings
from sec7669.orchestrator import build_default_orchestrator
from sec7669.otx_poller import run_otx_poll
from sec7669.state import OrchestratorState

app = typer.Typer(
    name="sec7669",
    help="Autonomous hunt draft orchestrator for ATHF.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _configure_logging(settings: Settings, *, to_stdout: bool = True) -> None:
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [logging.FileHandler(settings.log_file)]
    if to_stdout:
        handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


# --- Commands --------------------------------------------------------------


@app.command()
def run(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would happen without calling athf."),
    ] = False,
) -> None:
    """Execute one orchestrator cycle."""
    settings = Settings()  # type: ignore[call-arg]
    _configure_logging(settings)

    orch = build_default_orchestrator(settings)
    result = orch.run_once(dry_run=dry_run)

    console.print()
    console.print(f"[bold]Outcome:[/bold] {result.outcome}")
    if result.detail:
        console.print(f"[bold]Detail:[/bold] {result.detail}")
    if result.hunt_id:
        console.print(f"[bold]Hunt ID:[/bold] {result.hunt_id}")
    if result.research_id:
        console.print(f"[bold]Research ID:[/bold] {result.research_id}")
    if result.draft_path:
        console.print(f"[bold]Draft path:[/bold] {result.draft_path}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command(name="otx-poll")
def otx_poll() -> None:
    """Route the next high-signal OTX pulse into the CTI queue, if any."""
    settings = Settings()  # type: ignore[call-arg]
    _configure_logging(settings)

    result = run_otx_poll(settings)

    console.print()
    console.print(f"[bold]Routed:[/bold] {result.routed}")
    if result.routed_pulse_ids:
        console.print(f"[bold]Pulse ID:[/bold] {', '.join(result.routed_pulse_ids)}")
    if result.skipped_queue_occupied:
        console.print("[yellow]CTI queue slot occupied - skipped this poll.[/yellow]")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def status() -> None:
    """Show quota, last run, and total drafts."""
    settings = Settings()  # type: ignore[call-arg]
    state = OrchestratorState.load(settings.state_file)

    table = Table(title="sec7669 status", show_header=False)
    table.add_column("key", style="cyan")
    table.add_column("value")

    table.add_row("Version", __version__)
    table.add_row("ATHF workspace", str(settings.athf_workspace))
    table.add_row("CTI provider", settings.cti_provider)
    table.add_row("CTI queue dir", str(settings.cti_queue_dir_resolved))
    table.add_row("Model", f"{settings.athf_llm_provider}:{settings.athf_llm_model}")
    table.add_row("Drafts today", f"{state.drafts_today} / {settings.max_drafts_per_day}")
    table.add_row("Total drafts ever", str(state.total_drafts_ever))
    table.add_row("Last run", state.last_run_iso or "(never)")
    table.add_row("Consecutive failures", str(state.consecutive_failures))
    console.print(table)


@app.command()
def config() -> None:
    """Dump effective settings as JSON (safe for pasting into an issue)."""
    settings = Settings()  # type: ignore[call-arg]
    dumped = settings.redacted_dict()
    # Add derived paths for clarity
    dumped["_derived"] = {
        "athf_bin_resolved": str(settings.athf_bin_resolved),
        "cti_queue_dir_resolved": str(settings.cti_queue_dir_resolved),
        "hunts_root": str(settings.hunts_root),
        "log_file": str(settings.log_file),
        "state_file": str(settings.state_file),
    }
    console.print_json(json.dumps(dumped))


@app.command()
def doctor() -> None:
    """Sanity-check the deployment. Non-zero exit code if anything is off."""
    settings = Settings()  # type: ignore[call-arg]
    problems: list[str] = []

    def check(condition: bool, label: str, remediation: str) -> None:
        status_mark = "[green]✓[/green]" if condition else "[red]✗[/red]"
        console.print(f"{status_mark} {label}")
        if not condition:
            console.print(f"    [yellow]fix:[/yellow] {remediation}")
            problems.append(label)

    def warn(condition: bool, label: str, remediation: str) -> None:
        """Like `check`, but doesn't fail the command or set a non-zero exit."""
        status_mark = "[green]✓[/green]" if condition else "[yellow]![/yellow]"
        console.print(f"{status_mark} {label}")
        if not condition:
            console.print(f"    [yellow]note:[/yellow] {remediation}")

    check(
        settings.athf_workspace.exists(),
        f"ATHF workspace exists: {settings.athf_workspace}",
        "Set ATHF_WORKSPACE or run `athf init`",
    )
    check(
        settings.athf_bin_resolved.exists(),
        f"athf CLI at {settings.athf_bin_resolved}",
        "Install ATHF inside a venv and set ATHF_BIN if not at default location",
    )
    check(
        settings.hunts_root.exists() or settings.athf_workspace.exists(),
        f"Hunts root writable: {settings.hunts_root}",
        "Run `athf init` inside the workspace",
    )
    check(
        _has_write(settings.log_dir),
        f"Log dir writable: {settings.log_dir}",
        f"chmod +w {settings.log_dir}",
    )
    check(
        _has_write(settings.cti_queue_dir_resolved)
        or not settings.cti_queue_dir_resolved.exists(),
        f"CTI queue dir writable: {settings.cti_queue_dir_resolved}",
        f"mkdir -p and chmod +w {settings.cti_queue_dir_resolved}",
    )
    if settings.cti_provider == "otx":
        check(
            bool(settings.otx_api_key),
            "OTX_API_KEY set (required for cti_provider=otx)",
            "Set OTX_API_KEY in .env — get a free-tier key at https://otx.alienvault.com",
        )
    if settings.research_enabled:
        warn(
            _tavily_key_available(settings),
            "TAVILY_API_KEY set (research grounding is mandatory-when-enabled)",
            "Research will still run without it, but skips the adversary-tradecraft "
            "web-search skill — set TAVILY_API_KEY in the ATHF workspace .env for full "
            "grounding. Get a free-tier key at https://tavily.com",
        )
    warn(
        bool(settings.slack_webhook_url),
        "SEC7669_SLACK_WEBHOOK_URL set (draft-created notifications)",
        "Optional — without it, drafts land silently in hunts/production/ with no alert.",
    )

    if problems:
        console.print(f"\n[red]{len(problems)} problem(s) found[/red]")
        raise typer.Exit(code=1)
    console.print("\n[green]All checks passed.[/green]")


# --- Helpers ---------------------------------------------------------------


def _tavily_key_available(settings: Settings) -> bool:
    """Check both places TAVILY_API_KEY could actually reach the athf subprocess.

    ``athf``'s own CLI calls ``load_dotenv()`` from its cwd (the ATHF
    workspace) independently of whatever env sec7669 was started with — so
    the key being absent from sec7669's own process env doesn't mean
    research will run ungrounded; it may already be set in the workspace's
    own .env file.
    """
    if os.getenv("TAVILY_API_KEY"):
        return True
    workspace_env = settings.athf_workspace / ".env"
    if workspace_env.exists():
        return bool(dotenv_values(workspace_env).get("TAVILY_API_KEY"))
    return False


def _has_write(path: Path) -> bool:
    """Return True if the path (or its nearest existing parent) is writable."""
    check_target = path
    while not check_target.exists():
        check_target = check_target.parent
    import os as _os
    return _os.access(check_target, _os.W_OK)


if __name__ == "__main__":
    app()
