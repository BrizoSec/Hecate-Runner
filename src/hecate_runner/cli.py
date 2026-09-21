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

import importlib.util
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Annotated

import typer
from dotenv import dotenv_values
from rich.console import Console
from rich.table import Table

from hecate_runner import __version__
from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.grounding import TechniqueFact, render_grounding_section
from hecate_runner.hecate_client import HecateClient
from hecate_runner.hunt_audit import (
    HuntFacts,
    audit_hunt_text,
    parse_hunt_file,
    replace_grounding_section,
    research_text_for,
)
from hecate_runner.log_rotation import rotate_log_if_needed
from hecate_runner.misp_poller import run_misp_poll
from hecate_runner.orchestrator import build_default_orchestrator
from hecate_runner.otx_poller import run_otx_poll
from hecate_runner.parked_store import get_parked, list_parked, parked_dir, restore
from hecate_runner.query_execution import ProposedQuery, get_provider, validate_guardrails
from hecate_runner.query_store import PendingQueryStore
from hecate_runner.rss_poller import run_rss_poll
from hecate_runner.state import OrchestratorState

app = typer.Typer(
    name="hecate-runner",
    help="Autonomous hunt draft orchestrator for Hecate.",
    no_args_is_help=True,
    add_completion=False,
)
#: Technique IDs anywhere in a draft, so --check-attack validates the ones the
#: hunt actually records rather than only those its CTI named.
_DRAFT_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

console = Console()


def _stdout_already_targets(path: Path) -> bool:
    """True if sys.stdout is already writing to the same file as `path`.

    Under systemd, StandardOutput=append:<path> makes stdout point at the
    log file before our process even starts -- adding a separate
    logging.FileHandler(path) on top of a StreamHandler(sys.stdout) then
    doubles every line, since both end up writing to the same file. This
    check is redirection-mechanism-agnostic (systemd, shell `>>`, anything)
    rather than sniffing for systemd specifically, so it degrades safely:
    interactive runs (stdout is a terminal/pipe, not this file) are
    unaffected and still get both handlers as before.
    """
    try:
        stdout_stat = os.fstat(sys.stdout.fileno())
        target_stat = path.stat()
    except OSError:
        return False
    return (stdout_stat.st_dev, stdout_stat.st_ino) == (target_stat.st_dev, target_stat.st_ino)


def _configure_logging(settings: Settings, *, to_stdout: bool = True) -> None:
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    # Rotate before any handler opens the file. The orchestrator is a oneshot
    # unit, so "at startup" is the only moment both writers -- this process and
    # systemd's append: redirection -- are between writes.
    rotate_log_if_needed(
        settings.log_file,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
    )
    handlers: list[logging.Handler] = [logging.FileHandler(settings.log_file)]
    if to_stdout and not _stdout_already_targets(settings.log_file):
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
        typer.Option("--dry-run", help="Show what would happen without calling hecate."),
    ] = False,
) -> None:
    """Execute one orchestrator cycle."""
    settings = Settings()
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
    settings = Settings()
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
    settings = Settings()
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
    settings = Settings()
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
    time_range_days: Annotated[
        int, typer.Option("--time-range-days", help="Bounded lookback window")
    ],
    limit: Annotated[int, typer.Option("--limit", help="Max results")],
    justification: Annotated[
        str, typer.Option("--justification", help="Why this query, why these bounds")
    ] = "",
) -> None:
    """Stage a bounded query for a hunt. Rejected outright if it violates guardrails.

    This does not execute anything — it only stages a proposal for
    `hecate-runner approve` to run later. Nothing here writes queries for you;
    you (or, in the future, a separately-evaluated agent) provide the query
    text.
    """
    settings = Settings()
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
    console.print(
        f"  Data source: {data_source}  |  Time range: {time_range_days}d  |  Limit: {limit}"
    )
    console.print(
        f"\nRun [bold]hecate-runner approve {hunt_id}[/bold] to execute, or [bold]hecate-runner reject {hunt_id}[/bold] to discard."
    )


@app.command()
def audit(
    hunt_ids: Annotated[
        list[str] | None,
        typer.Argument(help="Hunt IDs to audit (e.g. H-0616). Omit to audit every hunt on disk."),
    ] = None,
    update: Annotated[
        bool,
        typer.Option(
            "--update", help="Rewrite each hunt's Grounding section with the fresh result."
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict", help="Exit non-zero if any hunt carries a claim that traces to no source."
        ),
    ] = False,
    check_attack: Annotated[
        bool,
        typer.Option(
            "--check-attack",
            help=(
                "Validate technique IDs against the live ATT&CK matrix. Off by "
                "default because it costs one hecate subprocess per technique."
            ),
        ),
    ] = False,
) -> None:
    """Re-grade hunts already on disk against the evidence behind them.

    The audit normally runs while a hunt is drafted, so every hunt written
    before a given version of it was graded by an older one -- or, for drafts
    predating the audit, not at all. This re-runs it after the fact.
    """
    settings = Settings()
    _configure_logging(settings, to_stdout=False)

    paths = _hunt_paths(settings, hunt_ids)
    if not paths:
        console.print("[yellow]No hunt files matched.[/yellow]")
        raise typer.Exit(code=1 if hunt_ids else 0)

    hecate = HecateClient(
        workspace=settings.hecate_workspace,
        hecate_bin=settings.hecate_bin_resolved,
        env_overrides=settings.env_for_hecate(),
    )

    table = Table(title="Grounding audit", show_header=True, header_style="bold cyan")
    for column in ("Hunt", "CTI", "Asserted", "Research-only", "Inferred", "Unsupported"):
        table.add_column(column)

    total_unsupported = 0
    findings: list[tuple[str, list[str]]] = []

    for path in paths:
        text = path.read_text(encoding="utf-8")
        facts = parse_hunt_file(text)
        technique_facts = _attack_facts(hecate, settings, facts, text) if check_attack else None
        _, report = audit_hunt_text(
            text,
            research_text=research_text_for(settings.hecate_workspace, facts.research_id),
            technique_facts=technique_facts,
        )
        counts = report.counts
        total_unsupported += counts["unsupported"]
        if report.unsupported:
            findings.append((facts.hunt_id or path.stem, [c.value for c in report.unsupported]))

        table.add_row(
            facts.hunt_id or path.stem,
            # A hunt whose CTI could not be recovered is called out rather than
            # scored: every claim would grade unsupported for want of evidence,
            # which reads as a fabrication finding and is not one.
            "[green]ok[/green]" if facts.has_cti else "[yellow]not found[/yellow]",
            str(counts["asserted"]),
            str(counts["corroborated"]),
            str(counts["derived"]),
            f"[red]{counts['unsupported']}[/red]" if counts["unsupported"] else "0",
        )

        if update:
            refreshed = replace_grounding_section(text, render_grounding_section(report))
            if refreshed != text:
                atomic_write_text(path, refreshed)

    console.print(table)
    for hunt_id, values in findings:
        console.print(f"[red]{hunt_id}[/red]: {', '.join(values)}")
    if update:
        console.print(f"\n[dim]Grounding sections rewritten for {len(paths)} hunt(s).[/dim]")

    if strict and total_unsupported:
        raise typer.Exit(code=1)


def _hunt_paths(settings: Settings, hunt_ids: list[str] | None) -> list[Path]:
    """Resolve hunt IDs to files, or every hunt when none are named."""
    root = settings.hunts_root
    if not hunt_ids:
        return sorted(root.rglob("H-*.md"))
    resolved: list[Path] = []
    for hunt_id in hunt_ids:
        matches = sorted(root.rglob(f"{hunt_id}.md"))
        if not matches:
            console.print(f"[yellow]No file found for {hunt_id}.[/yellow]")
            continue
        resolved.extend(matches)
    return resolved


def _attack_facts(
    hecate: HecateClient, settings: Settings, facts: HuntFacts, text: str
) -> dict[str, TechniqueFact]:
    """Look every technique in the draft up against the live matrix."""
    collected: dict[str, TechniqueFact] = {}
    for technique_id in sorted(set(_DRAFT_TECHNIQUE_RE.findall(text))):
        meta = hecate.lookup_technique(technique_id, timeout_sec=settings.llm_timeout_sec)
        collected[technique_id.upper()] = TechniqueFact(
            valid=meta.found,
            superseded_by=meta.technique_id if meta.superseded_from else "",
        )
    return collected


@app.command()
def pending() -> None:
    """List queries awaiting approval."""
    settings = Settings()
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
        table.add_row(
            q.hunt_id,
            q.data_source,
            f"{q.time_range_days}d",
            str(q.limit),
            q.proposed_at,
            q.query_text,
        )
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
    system when HECATE_RUNNER_QUERY_PROVIDER is set to a real backend; it's the
    deliberate human checkpoint the rest of the pipeline is built around.
    """
    settings = Settings()
    _configure_logging(settings, to_stdout=False)
    store = PendingQueryStore(settings.pending_queries_dir)
    proposed = store.load(hunt_id)

    if proposed is None:
        console.print(
            f"[red]No pending query for {hunt_id}.[/red] Run `hecate-runner pending` to see what's staged."
        )
        raise typer.Exit(code=1)

    violations = validate_guardrails(
        proposed,
        max_time_range_days=settings.max_query_time_range_days,
        max_limit=settings.max_query_limit,
    )
    if violations:
        console.print(
            f"[red]Refusing to execute — {len(violations)} guardrail violation(s) on re-check:[/red]"
        )
        for v in violations:
            console.print(f"  [red]✗[/red] {v}")
        console.print(
            "[dim]Left staged — fix and re-propose, or `hecate-runner reject` to discard.[/dim]"
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]Hunt:[/bold] {proposed.hunt_id}")
    console.print(
        f"[bold]Data source:[/bold] {proposed.data_source} (provider: {settings.query_provider})"
    )
    console.print(f"[bold]Query:[/bold] {proposed.query_text}")
    console.print(
        f"[bold]Time range:[/bold] {proposed.time_range_days}d  [bold]Limit:[/bold] {proposed.limit}"
    )
    if proposed.justification:
        console.print(f"[bold]Justification:[/bold] {proposed.justification}")

    if not yes and not typer.confirm("\nExecute this query?"):
        console.print("[yellow]Cancelled — query remains staged.[/yellow]")
        raise typer.Exit(code=1)

    provider = get_provider(
        settings.query_provider,
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
    )
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
        console.print(
            "[dim]Left staged since execution failed — retry with `hecate-runner approve` once fixed.[/dim]"
        )

    raise typer.Exit(code=0 if result.ok else 1)


@app.command()
def reject(
    hunt_id: Annotated[str, typer.Argument(help="Hunt whose pending query should be discarded")],
    reason: Annotated[str | None, typer.Option("--reason", help="Why, for the log")] = None,
) -> None:
    """Discard a proposed query without executing it."""
    settings = Settings()
    store = PendingQueryStore(settings.pending_queries_dir)
    proposed = store.load(hunt_id)

    if proposed is None:
        console.print(f"[red]No pending query for {hunt_id}.[/red]")
        raise typer.Exit(code=1)

    store.remove(hunt_id)
    console.print(
        f"[green]✓[/green] Rejected pending query for {hunt_id}"
        + (f" ({reason})" if reason else "")
    )


@app.command()
def status() -> None:
    """Show quota, last run, and total drafts."""
    settings = Settings()
    state = OrchestratorState.load(settings.state_file)

    table = Table(title="hecate-runner status", show_header=False)
    table.add_column("key", style="cyan")
    table.add_column("value")

    table.add_row("Version", __version__)
    table.add_row("Hecate workspace", str(settings.hecate_workspace))
    table.add_row("CTI provider", settings.cti_provider)
    table.add_row("CTI queue dir", str(settings.cti_queue_dir_resolved))
    table.add_row("Model", _effective_model(settings))
    table.add_row("Drafts today", f"{state.drafts_today} / {settings.max_drafts_per_day}")
    table.add_row("Total drafts ever", str(state.total_drafts_ever))
    table.add_row("Last run", state.last_run_iso or "(never)")
    table.add_row("Consecutive failures", str(state.consecutive_failures))

    from hecate_runner.parked_store import list_parked

    parked_count = len(list_parked(settings.cti_queue_dir_resolved))
    table.add_row("Parked drafts", str(parked_count))
    console.print(table)


parked_app = typer.Typer(help="Inspect and restore CTI held back by intake triage.")
app.add_typer(parked_app, name="parked")


@parked_app.command("list")
def parked_list() -> None:
    """List CTI held back by triage, newest first."""
    settings = Settings()
    items = list_parked(settings.cti_queue_dir_resolved)
    if not items:
        console.print("Nothing parked.")
        return

    table = Table(title="Parked CTI")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Parked")
    table.add_column("Source")
    table.add_column("Title")
    table.add_column("Why it was held back")
    for item in items:
        table.add_row(
            item.park_id,
            item.parked_at[:16].replace("T", " "),
            item.source,
            (item.title or "(untitled)")[:44],
            item.reason[:52],
        )
    console.print(table)
    console.print(
        f"\n{len(items)} item(s) in {parked_dir(settings.cti_queue_dir_resolved)}. "
        "Restore one with [bold]hecate-runner parked restore <id>[/bold]."
    )


@parked_app.command("show")
def parked_show(
    park_id: Annotated[str, typer.Argument(help="Parked item id, or an unambiguous prefix.")],
) -> None:
    """Print a parked item in full."""
    settings = Settings()
    item = get_parked(settings.cti_queue_dir_resolved, park_id)
    if item is None:
        console.print(f"[red]No parked item matching {park_id!r}.[/red]")
        raise typer.Exit(1)
    console.print(
        f"[bold]{item.park_id}[/bold]  ({item.source}, parked {item.parked_at[:16].replace('T', ' ')})"
    )
    console.print(f"[bold]Held back because:[/bold] {item.reason}")
    if item.source_url:
        console.print(f"[bold]Link:[/bold] {item.source_url}")
    console.print("")
    console.print(item.content)


@parked_app.command("restore")
def parked_restore(
    park_id: Annotated[str, typer.Argument(help="Parked item id, or an unambiguous prefix.")],
) -> None:
    """Put a parked item back on the file queue so a cycle picks it up."""
    settings = Settings()
    item = get_parked(settings.cti_queue_dir_resolved, park_id)
    if item is None:
        console.print(f"[red]No parked item matching {park_id!r}.[/red]")
        raise typer.Exit(1)

    next_file = settings.cti_next_file
    if next_file.exists() and next_file.read_text().strip():
        console.print(
            f"[red]{next_file} already holds CTI.[/red] The file queue takes one item at a "
            "time; restoring now would overwrite it. Let the next cycle consume it first."
        )
        raise typer.Exit(1)

    restore(settings.cti_queue_dir_resolved, item)
    console.print(f"Restored [cyan]{item.park_id}[/cyan] to {next_file}.")

    # The restored item only gets picked up if the file provider is actually
    # in the rotation, which it is not in a default multi-provider setup.
    configured = (
        settings.cti_multi_provider_names
        if settings.cti_provider == "multi"
        else [settings.cti_provider]
    )
    if "file" not in configured:
        console.print(
            "\n[yellow]Note:[/yellow] the file queue is not in your CTI rotation "
            f"(currently: {', '.join(configured)}), so nothing will read it. Add "
            "[bold]file[/bold] to HECATE_RUNNER_CTI_MULTI_PROVIDERS to have the next "
            "cycle pick this up."
        )


@app.command()
def config() -> None:
    """Dump effective settings as JSON (safe for pasting into an issue)."""
    settings = Settings()
    dumped = settings.redacted_dict()
    # Add derived paths for clarity
    dumped["_derived"] = {
        "hecate_bin_resolved": str(settings.hecate_bin_resolved),
        "cti_queue_dir_resolved": str(settings.cti_queue_dir_resolved),
        "hunts_root": str(settings.hunts_root),
        "log_file": str(settings.log_file),
        "state_file": str(settings.state_file),
    }
    console.print_json(json.dumps(dumped))


@app.command()
def doctor() -> None:
    """Sanity-check the deployment. Non-zero exit code if anything is off."""
    settings = Settings()
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
        settings.hecate_workspace.exists(),
        f"Hecate workspace exists: {settings.hecate_workspace}",
        "Set HECATE_WORKSPACE or run `hecate init`",
    )
    check(
        settings.hecate_bin_resolved.exists(),
        f"hecate-agent CLI at {settings.hecate_bin_resolved}",
        "Install Hecate inside a venv and set HECATE_BIN if not at default location",
    )
    check(
        settings.hunts_root.exists() or settings.hecate_workspace.exists(),
        f"Hunts root writable: {settings.hunts_root}",
        "Run `hecate init` inside the workspace",
    )
    check(
        _has_write(settings.log_dir),
        f"Log dir writable: {settings.log_dir}",
        f"chmod +w {settings.log_dir}",
    )
    check(
        _has_write(settings.cti_queue_dir_resolved) or not settings.cti_queue_dir_resolved.exists(),
        f"CTI queue dir writable: {settings.cti_queue_dir_resolved}",
        f"mkdir -p and chmod +w {settings.cti_queue_dir_resolved}",
    )
    if settings.cti_provider == "multi":
        multi_names = settings.cti_multi_provider_names
        check(
            bool(multi_names) and "multi" not in multi_names,
            f"HECATE_RUNNER_CTI_MULTI_PROVIDERS valid ({', '.join(multi_names) or 'empty'})",
            "Set HECATE_RUNNER_CTI_MULTI_PROVIDERS to a comma-separated list from: file, otx, rss, misp.",
        )
    else:
        multi_names = []
    active_cti_providers = (
        multi_names if settings.cti_provider == "multi" else [settings.cti_provider]
    )

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
        "Set HECATE_RUNNER_RSS_FEED_URLS to a comma-separated list of feed URLs.",
    )

    # --- Agent capabilities ------------------------------------------------
    # The runner drives hecate_agent in-process, so its optional capabilities
    # resolve against *this* environment, not the workspace venv HECATE_BIN
    # points at. Checking an API key without checking the client library that
    # consumes it is what let research grounding sit switched off unnoticed:
    # the key was set, the package was absent, and every cycle still reported
    # success. These are hard checks -- the runner treats all of hecate_agent's
    # optional capabilities as mandatory.
    check(
        _module_available("mitreattack"),
        "mitreattack-python importable (ATT&CK technique lookup)",
        "Reinstall the runner with `uv sync` — hecate-agent[all] carries it.",
    )
    # The package alone is not enough. Lookup needs the downloaded STIX bundle,
    # and without it every technique ID resolves to nothing, so drafts ship with
    # empty `techniques:` frontmatter and invented IDs go uncaught.
    check(
        _stix_data_available(),
        "ATT&CK STIX data present (technique validation and enrichment)",
        "Run `hecate-agent attack update` to download the STIX bundle.",
    )
    check(
        _module_available("sklearn"),
        "scikit-learn importable (related-hunt similarity)",
        "Reinstall the runner with `uv sync` — hecate-agent[all] carries it.",
    )
    check(
        _module_available("sigma"),
        "pySigma importable (Sigma rule validation)",
        "Reinstall the runner with `uv sync` — without it generated rules are "
        "only structurally checked, never validated as Sigma.",
    )
    if settings.research_enabled:
        check(
            _module_available("tavily"),
            "tavily-python importable (research web grounding)",
            "Reinstall the runner with `uv sync` — without it research silently runs ungrounded.",
        )
        # Promoted from a warning: with the client library mandatory, a missing
        # key is the only remaining way for grounding to be off, and the old
        # note ("research will still run without it") described exactly the
        # silent degradation this check exists to prevent.
        check(
            _tavily_key_available(settings),
            "TAVILY_API_KEY set (research grounding is mandatory-when-enabled)",
            "Set TAVILY_API_KEY in the Hecate workspace .env. Get a free-tier "
            "key at https://tavily.com, or set HECATE_RUNNER_RESEARCH_ENABLED=false "
            "to run drafts without research grounding deliberately.",
        )
    warn(
        bool(settings.slack_webhook_url),
        "HECATE_RUNNER_SLACK_WEBHOOK_URL set (draft-created notifications)",
        "Optional — without it, drafts land silently in hunts/ with no alert.",
    )
    if settings.query_provider == "splunk":
        check(
            _env_key_available(settings, "SPLUNK_HOST")
            and _env_key_available(settings, "SPLUNK_TOKEN"),
            "SPLUNK_HOST / SPLUNK_TOKEN set (required for HECATE_RUNNER_QUERY_PROVIDER=splunk)",
            "Set both in the Hecate workspace .env — see `hecate-agent splunk test` to verify connectivity "
            "before running `hecate-runner approve` against it.",
        )
    else:
        console.print(
            f"[dim]i Query provider is '{settings.query_provider}' — `hecate-runner approve` cannot touch a real "
            "system yet. Set HECATE_RUNNER_QUERY_PROVIDER=splunk once real access exists.[/dim]"
        )

    if problems:
        console.print(f"\n[red]{len(problems)} problem(s) found[/red]")
        raise typer.Exit(code=1)
    console.print("\n[green]All checks passed.[/green]")


# --- Helpers ---------------------------------------------------------------


def _effective_model(settings: Settings) -> str:
    """Render the LLM the hecate subprocess will actually use.

    Unset here means the workspace's own .env supplies it, so resolve from
    there rather than printing a placeholder -- the point of the row is to
    show what will run, and "(workspace)" answers a different question.
    """
    provider = settings.hecate_llm_provider or _workspace_env_value(settings, "HECATE_LLM_PROVIDER")
    model = settings.hecate_llm_model or _workspace_env_value(settings, "HECATE_LLM_MODEL")
    if not provider and not model:
        return "(hecate autodetects — none set here or in the workspace .env)"
    suffix = (
        "" if (settings.hecate_llm_provider or settings.hecate_llm_model) else "  (from workspace)"
    )
    return f"{provider or '?'}:{model or '?'}{suffix}"


def _workspace_env_value(settings: Settings, key_name: str) -> str:
    """Read one key from the Hecate workspace's own .env, or "" if absent."""
    if os.getenv(key_name):
        return os.environ[key_name]
    workspace_env = settings.hecate_workspace / ".env"
    if workspace_env.exists():
        return dotenv_values(workspace_env).get(key_name) or ""
    return ""


def _env_key_available(settings: Settings, key_name: str) -> bool:
    """Check both places an Hecate-subprocess-only env var could actually be set.

    ``hecate-agent``'s own CLI calls ``load_dotenv()`` from its cwd (the Hecate
    workspace) independently of whatever env hecate-runner was started with — so
    a key being absent from hecate-runner's own process env doesn't mean the hecate
    subprocess won't see it; it may already be set in the workspace's own
    .env file.
    """
    if os.getenv(key_name):
        return True
    workspace_env = settings.hecate_workspace / ".env"
    if workspace_env.exists():
        return bool(dotenv_values(workspace_env).get(key_name))
    return False


def _tavily_key_available(settings: Settings) -> bool:
    return _env_key_available(settings, "TAVILY_API_KEY")


def _module_available(name: str) -> bool:
    """True if `name` can be imported in *this* interpreter.

    find_spec rather than a real import: the point is whether the dependency is
    installed here, and importing heavyweight ML packages just to answer that
    would make `doctor` slow enough that people stop running it.
    """
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _stix_data_available() -> bool:
    """True if ATT&CK lookups are backed by live STIX data, not the fallback.

    Distinct from `_module_available("mitreattack")`: the provider needs both
    the package and a downloaded bundle, and silently falls back when either is
    missing.
    """
    try:
        from hecate_agent.core.attack_matrix import is_using_stix

        return bool(is_using_stix())
    except Exception:
        return False


def _has_write(path: Path) -> bool:
    """Return True if the path (or its nearest existing parent) is writable."""
    check_target = path
    while not check_target.exists():
        check_target = check_target.parent
    import os as _os

    return _os.access(check_target, _os.W_OK)


# --- Sources Configuration UX ----------------------------------------------


sources_app = typer.Typer(help="Manage CTI sources (list, enable, disable, reset).")
app.add_typer(sources_app, name="sources")


@sources_app.command("list")
def list_sources() -> None:
    """List all CTI sources, their configuration status, and active state."""
    from rich.console import Console
    from rich.table import Table

    from hecate_runner.config import Settings

    settings = Settings()
    console = Console()

    table = Table(title="CTI Sources Configuration")
    table.add_column("Provider", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Credentials / Configured", style="dim")
    table.add_column("Cursor State")

    is_multi = settings.cti_provider == "multi"
    active_sources = settings.cti_multi_provider_names if is_multi else [settings.cti_provider]

    def format_active(name: str) -> str:
        return "[green]Active[/green]" if name in active_sources else "[dim]Disabled[/dim]"

    def cursor_status(path: Path) -> str:
        if path.exists():
            import datetime
            import os

            mtime = os.path.getmtime(path)
            dt = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
            return f"Exists (last updated {dt})"
        return "None"

    # OTX
    otx_cred = "API Key present" if settings.otx_api_key else "Missing API Key"
    table.add_row("otx", format_active("otx"), otx_cred, cursor_status(settings.otx_cursor_file))

    # MISP
    misp_cred = (
        "Configured" if settings.misp_base_url and settings.misp_api_key else "Missing Config"
    )
    table.add_row(
        "misp", format_active("misp"), misp_cred, cursor_status(settings.misp_cursor_file)
    )

    # RSS
    rss_cred = f"{len(settings.rss_feed_urls)} feeds" if settings.rss_feed_urls else "No feeds"
    table.add_row("rss", format_active("rss"), rss_cred, cursor_status(settings.rss_cursor_file))

    # CISA KEV
    cisa_cursor = settings.hecate_workspace / ".cursors" / "cisa_kev_cursor.json"
    table.add_row(
        "cisa_kev", format_active("cisa_kev"), "Built-in (Public)", cursor_status(cisa_cursor)
    )

    # abuse_ch
    table.add_row(
        "abuse_ch", format_active("abuse_ch"), "ThreatFox (Public JSON)", cursor_status(settings.abuse_ch_cursor_file)
    )

    # File Queue
    file_queue_dir = settings.cti_queue_dir_resolved
    file_status = (
        f"{len(list(file_queue_dir.glob('*.txt')))} items"
        if file_queue_dir.exists()
        else "Missing dir"
    )
    table.add_row("file", format_active("file"), file_status, "N/A")

    console.print(table)

    if is_multi:
        console.print(
            f"\n[dim]Multi-provider round-robin cursor:[/dim] {cursor_status(settings.multi_cursor_file)}\n"
        )


def _update_env_key(key: str, value: str) -> None:
    import os

    from dotenv import set_key

    env_path = ".env"
    if not os.path.exists(env_path):
        with open(env_path, "w"):
            pass
    set_key(env_path, key, value)


@sources_app.command("enable")
def enable_source(name: str) -> None:
    """Enable a CTI source in the .env configuration."""
    from rich.console import Console

    from hecate_runner.config import Settings

    settings = Settings()
    console = Console()

    valid = {"otx", "rss", "misp", "cisa_kev", "abuse_ch", "file"}
    if name not in valid:
        console.print(
            f"[red]Error:[/red] Unknown source '{name}'. Valid sources are: {', '.join(valid)}"
        )
        raise typer.Exit(1)

    active = (
        settings.cti_multi_provider_names
        if settings.cti_provider == "multi"
        else [settings.cti_provider]
    )
    if name in active:
        console.print(f"Source [cyan]{name}[/cyan] is already enabled.")
        return

    if settings.cti_provider == "file" and name != "file":
        # Usually want to switch to multi if enabling a real feed while on file queue
        new_active = [name] if settings.cti_provider == "file" else [*active, name]
    else:
        new_active = [*active, name]

    # If more than one active, must be 'multi'
    if len(new_active) > 1:
        _update_env_key("HECATE_RUNNER_CTI_PROVIDER", "multi")
        # Remove 'file' from multi if it's there as multi doesn't normally include file well? Wait, multi works with file.
        _update_env_key("HECATE_RUNNER_CTI_MULTI_PROVIDERS", ",".join(new_active))
        console.print(f"Enabled [cyan]{name}[/cyan] (Mode: multi, Active: {','.join(new_active)})")
    else:
        _update_env_key("HECATE_RUNNER_CTI_PROVIDER", name)
        console.print(f"Enabled [cyan]{name}[/cyan] as the primary CTI provider.")


@sources_app.command("disable")
def disable_source(name: str) -> None:
    """Disable a CTI source in the .env configuration."""
    from rich.console import Console

    from hecate_runner.config import Settings

    settings = Settings()
    console = Console()

    if settings.cti_provider != "multi":
        if settings.cti_provider == name:
            console.print(
                "[yellow]Cannot disable the only active source.[/yellow] Set a new primary source first, or enable another."
            )
            raise typer.Exit(1)
        else:
            console.print(f"Source [cyan]{name}[/cyan] is already disabled.")
            return

    active = settings.cti_multi_provider_names
    if name not in active:
        console.print(f"Source [cyan]{name}[/cyan] is already disabled.")
        return

    new_active = [a for a in active if a != name]

    if len(new_active) == 1:
        _update_env_key("HECATE_RUNNER_CTI_PROVIDER", new_active[0])
        console.print(
            f"Disabled [cyan]{name}[/cyan]. Reverted to single provider mode: {new_active[0]}"
        )
    else:
        _update_env_key("HECATE_RUNNER_CTI_MULTI_PROVIDERS", ",".join(new_active))
        console.print(f"Disabled [cyan]{name}[/cyan]. Remaining active: {','.join(new_active)}")


@sources_app.command("reset")
def reset_cursor(name: str) -> None:
    """Reset a CTI source's cursor to force re-ingestion."""
    import os

    from rich.console import Console

    from hecate_runner.config import Settings

    settings = Settings()
    console = Console()

    cursors = {
        "otx": settings.otx_cursor_file,
        "misp": settings.misp_cursor_file,
        "rss": settings.rss_cursor_file,
        "multi": settings.multi_cursor_file,
        "cisa_kev": settings.hecate_workspace / ".cursors" / "cisa_kev_cursor.json",
        "abuse_ch": settings.abuse_ch_cursor_file,
    }

    if name not in cursors:
        console.print(f"[red]Error:[/red] Unknown source or source without cursor '{name}'.")
        raise typer.Exit(1)

    cursor_path = cursors[name]
    if cursor_path.exists():
        try:
            os.remove(cursor_path)
            console.print(f"[green]Successfully reset cursor for {name}.[/green]")
        except Exception as e:
            console.print(f"[red]Failed to delete cursor:[/red] {e}")
            raise typer.Exit(1) from e
    else:
        console.print(f"No cursor found for [cyan]{name}[/cyan] at {cursor_path}")


if __name__ == "__main__":
    app()
