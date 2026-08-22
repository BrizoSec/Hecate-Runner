"""Typer-based CLI entry point.

Commands:
    hecate-runner run           Execute one orchestrator cycle
    hecate-runner status        Print state, quota, config summary
    hecate-runner config        Dump effective config (redacts secrets)
    hecate-runner doctor        Sanity-check the deployment
    hecate-runner otx-poll      Route one high-signal OTX pulse into the CTI queue
    hecate-runner rss-poll      Route one high-signal RSS/Atom entry into the CTI queue
    hecate-runner misp-poll     Route one high-signal MISP event into the CTI queue
    hecate-runner propose       Stage a bounded query for a hunt, pending approval
    hecate-runner pending       List queries awaiting approval
    hecate-runner approve       Execute a previously proposed, guardrail-passed query
    hecate-runner reject        Discard a proposed query without executing it
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

from hecate_runner import __version__
from hecate_runner.config import Settings
from hecate_runner.misp_poller import run_misp_poll
from hecate_runner.orchestrator import build_default_orchestrator
from hecate_runner.otx_poller import run_otx_poll
from hecate_runner.query_execution import ProposedQuery, get_provider, validate_guardrails
from hecate_runner.query_store import PendingQueryStore
from hecate_runner.rss_poller import run_rss_poll
from hecate_runner.state import OrchestratorState

app = typer.Typer(
    name="hecate-runner",
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


@app.command(name="rss-poll")
def rss_poll() -> None:
    """Route the next high-signal RSS/Atom entry into the CTI queue, if any."""
    settings = Settings()  # type: ignore[call-arg]
    _configure_logging(settings)

    result = run_rss_poll(settings)

    console.print()
    console.print(f"[bold]Routed:[/bold] {result.routed}")
    if result.routed_entry_ids:
        console.print(f"[bold]Entry:[/bold] {', '.join(result.routed_entry_ids)}")
    if result.skipped_queue_occupied:
        console.print("[yellow]CTI queue slot occupied - skipped this poll.[/yellow]")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command(name="misp-poll")
def misp_poll() -> None:
    """Route the next high-signal MISP event into the CTI queue, if any."""
    settings = Settings()  # type: ignore[call-arg]
    _configure_logging(settings)

    result = run_misp_poll(settings)

    console.print()
    console.print(f"[bold]Routed:[/bold] {result.routed}")
    if result.routed_event_uuids:
        console.print(f"[bold]Event:[/bold] {', '.join(result.routed_event_uuids)}")
    if result.skipped_queue_occupied:
        console.print("[yellow]CTI queue slot occupied - skipped this poll.[/yellow]")
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def propose(
    hunt_id: Annotated[str, typer.Argument(help="Hunt this query is for, e.g. H-0016")],
    query: Annotated[str, typer.Option("--query", help="The query text (e.g. SPL)")],
    data_source: Annotated[str, typer.Option("--data-source", help="e.g. splunk")],
    time_range_days: Annotated[int, typer.Option("--time-range-days", help="Bounded lookback window")],
    limit: Annotated[int, typer.Option("--limit", help="Max results")],
    justification: Annotated[str, typer.Option("--justification", help="Why this query, why these bounds")] = "",
) -> None:
    """Stage a bounded query for a hunt. Rejected outright if it violates guardrails.

    This does not execute anything — it only stages a proposal for
    `hecate-runner approve` to run later. Nothing here writes queries for you;
    you (or, in the future, a separately-evaluated agent) provide the query
    text.
    """
    settings = Settings()  # type: ignore[call-arg]
    proposed = ProposedQuery(
        hunt_id=hunt_id,
        data_source=data_source,
        query_text=query,
        time_range_days=time_range_days,
        limit=limit,
        justification=justification,
    )

    violations = validate_guardrails(
        proposed,
        max_time_range_days=settings.max_query_time_range_days,
        max_limit=settings.max_query_limit,
    )
    if violations:
        console.print(f"[red]Query rejected — {len(violations)} guardrail violation(s):[/red]")
        for v in violations:
            console.print(f"  [red]✗[/red] {v}")
        raise typer.Exit(code=1)

    store = PendingQueryStore(settings.pending_queries_dir)
    path = store.save(proposed)
    console.print(f"[green]✓[/green] Proposed query staged for {hunt_id} at {path}")
    console.print(f"  Data source: {data_source}  |  Time range: {time_range_days}d  |  Limit: {limit}")
    console.print(f"\nRun [bold]hecate-runner approve {hunt_id}[/bold] to execute, or [bold]hecate-runner reject {hunt_id}[/bold] to discard.")


@app.command()
def pending() -> None:
    """List queries awaiting approval."""
    settings = Settings()  # type: ignore[call-arg]
    store = PendingQueryStore(settings.pending_queries_dir)
    queries = store.list_all()

    if not queries:
        console.print("[dim]No queries pending approval.[/dim]")
        return

    table = Table(title="Pending queries", show_header=True, header_style="bold cyan")
    table.add_column("Hunt")
    table.add_column("Data source")
    table.add_column("Range")
    table.add_column("Limit")
    table.add_column("Proposed at")
    table.add_column("Query", overflow="fold")
    for q in queries:
        table.add_row(q.hunt_id, q.data_source, f"{q.time_range_days}d", str(q.limit), q.proposed_at, q.query_text)
    console.print(table)


@app.command()
def approve(
    hunt_id: Annotated[str, typer.Argument(help="Hunt whose pending query should be executed")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt")] = False,
) -> None:
    """Execute a previously proposed, guardrail-passed query.

    Re-validates guardrails before executing — defense in depth in case the
    staged file was hand-edited or the configured ceilings changed since
    `propose` ran. This is the one command in hecate-runner that can touch a real
    system when SEC7669_QUERY_PROVIDER is set to a real backend; it's the
    deliberate human checkpoint the rest of the pipeline is built around.
    """
    settings = Settings()  # type: ignore[call-arg]
    _configure_logging(settings, to_stdout=False)
    store = PendingQueryStore(settings.pending_queries_dir)
    proposed = store.load(hunt_id)

    if proposed is None:
        console.print(f"[red]No pending query for {hunt_id}.[/red] Run `hecate-runner pending` to see what's staged.")
        raise typer.Exit(code=1)

    violations = validate_guardrails(
        proposed,
        max_time_range_days=settings.max_query_time_range_days,
        max_limit=settings.max_query_limit,
    )
    if violations:
        console.print(f"[red]Refusing to execute — {len(violations)} guardrail violation(s) on re-check:[/red]")
        for v in violations:
            console.print(f"  [red]✗[/red] {v}")
        console.print("[dim]Left staged — fix and re-propose, or `hecate-runner reject` to discard.[/dim]")
        raise typer.Exit(code=1)

    console.print(f"[bold]Hunt:[/bold] {proposed.hunt_id}")
    console.print(f"[bold]Data source:[/bold] {proposed.data_source} (provider: {settings.query_provider})")
    console.print(f"[bold]Query:[/bold] {proposed.query_text}")
    console.print(f"[bold]Time range:[/bold] {proposed.time_range_days}d  [bold]Limit:[/bold] {proposed.limit}")
    if proposed.justification:
        console.print(f"[bold]Justification:[/bold] {proposed.justification}")

    if not yes and not typer.confirm("\nExecute this query?"):
        console.print("[yellow]Cancelled — query remains staged.[/yellow]")
        raise typer.Exit(code=1)

    provider = get_provider(settings.query_provider, athf_bin=settings.athf_bin_resolved, workspace=settings.athf_workspace)
    result = provider.execute(proposed)

    console.print()
    console.print(f"[bold]Outcome:[/bold] {result.outcome}")
    console.print(f"[bold]Provider:[/bold] {result.provider}")
    console.print(f"[bold]Row count:[/bold] {result.row_count}")
    if result.detail:
        console.print(f"[bold]Detail:[/bold] {result.detail[:1000]}")

    if result.ok:
        store.remove(hunt_id)
    else:
        console.print("[dim]Left staged since execution failed — retry with `hecate-runner approve` once fixed.[/dim]")

    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def reject(
    hunt_id: Annotated[str, typer.Argument(help="Hunt whose pending query should be discarded")],
    reason: Annotated[str | None, typer.Option("--reason", help="Why, for the log")] = None,
) -> None:
    """Discard a proposed query without executing it."""
    settings = Settings()  # type: ignore[call-arg]
    store = PendingQueryStore(settings.pending_queries_dir)
    proposed = store.load(hunt_id)

    if proposed is None:
        console.print(f"[red]No pending query for {hunt_id}.[/red]")
        raise typer.Exit(code=1)

    store.remove(hunt_id)
    console.print(f"[green]✓[/green] Rejected pending query for {hunt_id}" + (f" ({reason})" if reason else ""))


@app.command()
def status() -> None:
    """Show quota, last run, and total drafts."""
    settings = Settings()  # type: ignore[call-arg]
    state = OrchestratorState.load(settings.state_file)

    table = Table(title="hecate-runner status", show_header=False)
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
    if settings.cti_provider == "multi":
        multi_names = settings.cti_multi_provider_names
        check(
            bool(multi_names) and "multi" not in multi_names,
            f"SEC7669_CTI_MULTI_PROVIDERS valid ({', '.join(multi_names) or 'empty'})",
            "Set SEC7669_CTI_MULTI_PROVIDERS to a comma-separated list from: file, otx, rss, misp.",
        )
    else:
        multi_names = []
    active_cti_providers = multi_names if settings.cti_provider == "multi" else [settings.cti_provider]

    if "otx" in active_cti_providers:
        check(
            bool(settings.otx_api_key),
            "OTX_API_KEY set (required — cti_provider includes 'otx')",
            "Set OTX_API_KEY in .env — get a free-tier key at https://otx.alienvault.com",
        )
    if "misp" in active_cti_providers:
        check(
            bool(settings.misp_base_url) and bool(settings.misp_api_key),
            "MISP_BASE_URL / MISP_API_KEY set (required — cti_provider includes 'misp')",
            "Set both in .env — use a dedicated automation key, not a personal user's key.",
        )
    # Checked unconditionally (not gated on cti_provider == "rss") because
    # `rss-poll` runs independently, same as `otx-poll` — most deployments
    # run the main loop on cti_provider=file and feed it via a poller timer.
    check(
        bool(settings.rss_feed_urls),
        f"RSS feed URLs configured ({len(settings.rss_feed_urls)} feeds)",
        "Set SEC7669_RSS_FEED_URLS to a comma-separated list of feed URLs.",
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
        "Optional — without it, drafts land silently in hunts/ with no alert.",
    )
    if settings.query_provider == "splunk":
        check(
            _env_key_available(settings, "SPLUNK_HOST") and _env_key_available(settings, "SPLUNK_TOKEN"),
            "SPLUNK_HOST / SPLUNK_TOKEN set (required for SEC7669_QUERY_PROVIDER=splunk)",
            "Set both in the ATHF workspace .env — see `athf splunk test` to verify connectivity "
            "before running `hecate-runner approve` against it.",
        )
    else:
        console.print(
            f"[dim]i Query provider is '{settings.query_provider}' — `hecate-runner approve` cannot touch a real "
            "system yet. Set SEC7669_QUERY_PROVIDER=splunk once real access exists.[/dim]"
        )

    if problems:
        console.print(f"\n[red]{len(problems)} problem(s) found[/red]")
        raise typer.Exit(code=1)
    console.print("\n[green]All checks passed.[/green]")


# --- Helpers ---------------------------------------------------------------


def _env_key_available(settings: Settings, key_name: str) -> bool:
    """Check both places an ATHF-subprocess-only env var could actually be set.

    ``athf``'s own CLI calls ``load_dotenv()`` from its cwd (the ATHF
    workspace) independently of whatever env hecate-runner was started with — so
    a key being absent from hecate-runner's own process env doesn't mean the athf
    subprocess won't see it; it may already be set in the workspace's own
    .env file.
    """
    if os.getenv(key_name):
        return True
    workspace_env = settings.athf_workspace / ".env"
    if workspace_env.exists():
        return bool(dotenv_values(workspace_env).get(key_name))
    return False


def _tavily_key_available(settings: Settings) -> bool:
    return _env_key_available(settings, "TAVILY_API_KEY")


def _has_write(path: Path) -> bool:
    """Return True if the path (or its nearest existing parent) is writable."""
    check_target = path
    while not check_target.exists():
        check_target = check_target.parent
    import os as _os
    return _os.access(check_target, _os.W_OK)


if __name__ == "__main__":
    app()
