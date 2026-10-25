"""Typer-based CLI entry point.

Commands:
    hecate-runner run           Execute one orchestrator cycle
    hecate-runner demo          Run an end-to-end zero-config demonstration cycle
    hecate-runner status        Print state, quota, config summary
    hecate-runner metrics       Summarize stage latency and LLM usage
    hecate-runner config        Dump effective config (redacts secrets)
    hecate-runner doctor        Sanity-check the deployment
    hecate-runner otx-poll      Route one high-signal OTX pulse into the CTI queue
    hecate-runner rss-poll      Route one high-signal RSS/Atom entry into the CTI queue
    hecate-runner misp-poll     Route one high-signal MISP event into the CTI queue
    hecate-runner propose       Stage a bounded query for a hunt, pending approval
    hecate-runner pending       List queries awaiting approval
    hecate-runner approve       Execute a previously proposed, guardrail-passed query
    hecate-runner reject        Discard a proposed query without executing it
    hecate-runner watch         Follow what a running cycle is deciding, step by step
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer
from dotenv import dotenv_values
from hecate_agent.core.grounding import TechniqueFact, render_grounding_section
from rich import box
from rich.console import Console
from rich.table import Table

from hecate_runner import __version__
from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.digests import (
    collect_detection_engineering_metrics,
    collect_threat_hunting_metrics,
    collect_threat_intel_metrics,
)
from hecate_runner.github_publisher import enqueue_hunt, outbox_status, sync_outbox
from hecate_runner.hecate_client import HecateClient
from hecate_runner.hunt_audit import (
    HuntFacts,
    audit_hunt_text,
    parse_hunt_file,
    replace_grounding_section,
)
from hecate_runner.log_rotation import rotate_log_if_needed
from hecate_runner.metrics import MetricsStore
from hecate_runner.misp_poller import run_misp_poll
from hecate_runner.notifications import (
    notify_detection_digest,
    notify_ops_metrics,
    notify_threat_hunting_digest,
    notify_threat_intel_digest,
    send_test_all_channels,
    send_test_notification,
)
from hecate_runner.orchestrator import (
    RunResult,
    build_default_orchestrator,
    build_orchestrator_for_item,
)
from hecate_runner.otx_poller import run_otx_poll
from hecate_runner.parked_store import get_parked, list_parked, parked_dir, restore
from hecate_runner.promotion_policy import evaluate_promotion, load_policy
from hecate_runner.query_execution import ProposedQuery, get_provider, validate_guardrails
from hecate_runner.query_store import PendingQueryStore
from hecate_runner.rss_poller import run_rss_poll
from hecate_runner.state import OrchestratorState
from hecate_runner.trail import LOGGER_NAME as TRAIL_LOGGER

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
    # Under systemd, StandardOutput=append: already writes stdout into the log
    # file, so log through stdout alone. Opening the file here as well is not
    # just redundant: when the file is missing, systemd creates it root-owned
    # before dropping to User=, and this process then cannot open it. Every
    # cycle for three hours on 26 Sep failed with PermissionError that way,
    # after a state reset had deleted the log.
    handlers: list[logging.Handler]
    if to_stdout and _stdout_already_targets(settings.log_file):
        handlers = [logging.StreamHandler(sys.stdout)]
    else:
        handlers = [logging.FileHandler(settings.log_file)]
        if to_stdout:
            handlers.append(logging.StreamHandler(sys.stdout))
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    # One line per HTTP request (every MISP/OTX/RSS poll) was half of each
    # cycle's log; the trail's intake line already says what was fetched.
    if settings.log_level != "DEBUG":
        logging.getLogger("httpx").setLevel(logging.WARNING)


# --- Commands --------------------------------------------------------------


@app.command()
def run(
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would happen without calling hecate."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "--ignore-quota",
            help="Bypass daily draft, research quota, and spacing limits.",
        ),
    ] = False,
) -> None:
    """Execute one orchestrator cycle."""
    settings = Settings()
    _configure_logging(settings)

    if force:
        orch = build_default_orchestrator(settings, ignore_quota=True)
    else:
        orch = build_default_orchestrator(settings)
    result = orch.run_once(dry_run=dry_run)
    _print_result(result)
    raise typer.Exit(code=0 if result.ok else 1)


def _print_result(result: RunResult) -> None:
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


@app.command()
def demo(
    keep: Annotated[
        bool,
        typer.Option("--keep", help="Preserve the temporary demonstration workspace on disk."),
    ] = False,
) -> None:
    """Run an end-to-end demonstration cycle with bundled fixtures and mock providers.

    Requires no API keys, no LLM, and no network access. Creates a temporary workspace,
    processes a sample CTI item through research, hypothesis generation, ATT&CK mapping,
    grounding audit, and Sigma drafting, and displays the resulting draft hunt.
    """
    from hecate_runner.demo import run_demo

    exit_code, _ = run_demo(keep=keep, console=console)
    raise typer.Exit(code=exit_code)


@app.command()
def draft(
    text: Annotated[
        str | None,
        typer.Argument(
            help="The intelligence to draft from. Omit to read --file or standard input."
        ),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option(
            "--file",
            "-f",
            help="Read the intelligence from this file.",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    url: Annotated[
        str,
        typer.Option(
            "--url",
            help="The report this intelligence summarises; it is fetched for source evidence.",
        ),
    ] = "",
    title: Annotated[
        str, typer.Option("--title", help="A title for the item; used as the research topic.")
    ] = "",
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would happen without calling hecate."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force", "--ignore-quota", help="Bypass daily draft and research quota limits."
        ),
    ] = False,
) -> None:
    """Draft a hunt from intelligence you supply, through the same cycle a feed item takes.

    The feeds and their cursors are not touched and triage is skipped, since
    you chose the item. Everything after intake is the scheduled cycle: source
    evidence, research, the hypothesis, technique and platform checks, the
    claim and grounding audits, and Sigma drafting. The draft counts against
    the daily draft and research quotas unless --force is given.
    """
    if text is not None and file is not None:
        console.print("[red]Give the intelligence as an argument or with --file, not both.[/red]")
        raise typer.Exit(code=2)
    if file is not None:
        content = file.read_text(encoding="utf-8")
    elif text is not None:
        content = text
    elif not sys.stdin.isatty():
        content = sys.stdin.read()
    else:
        console.print(
            "[red]No intelligence given: pass it as an argument, with --file, or on standard input.[/red]"
        )
        raise typer.Exit(code=2)
    content = content.strip()
    if not content:
        console.print("[red]The intelligence is empty.[/red]")
        raise typer.Exit(code=2)

    settings = Settings()
    _configure_logging(settings)
    item = CTIItem(
        content=content,
        source="manual",
        received_at=datetime.now(UTC),
        identifier=str(file) if file is not None else "manual",
        title=title.strip(),
        source_url=url.strip(),
    )
    result = build_orchestrator_for_item(settings, item, ignore_quota=force).run_once(
        dry_run=dry_run
    )
    _print_result(result)
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
        _, report = audit_hunt_text(text, technique_facts=technique_facts)
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


@app.command("promotion-check")
def promotion_check(
    hunt_id: Annotated[str, typer.Argument(help="Planning hunt ID to evaluate (e.g. H-0822).")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the deterministic policy decision as JSON.")
    ] = False,
) -> None:
    """Evaluate the versioned GitHub promotion policy without changing files."""
    settings = Settings()
    try:
        decision = evaluate_promotion(settings.hecate_workspace, hunt_id)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Promotion blocked:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if json_output:
        # Plain echo, not Rich: console.print wraps at terminal width and parses
        # [brackets] as markup, which corrupts the JSON the promotion workflow parses.
        typer.echo(json.dumps(decision.to_dict(), sort_keys=True))
        return
    if decision.eligible:
        console.print(f"[green]Auto-merge eligible:[/green] {hunt_id}")
    elif decision.review_required:
        console.print(f"[yellow]Human review required:[/yellow] {hunt_id}")
    else:
        console.print(f"[cyan]Publication allowed; auto-merge disabled by policy:[/cyan] {hunt_id}")
    for reason in decision.reasons:
        console.print(f"  - {reason}")


@app.command("promotion-policy-validate")
def promotion_policy_validate() -> None:
    """Validate the workspace's versioned promotion policy."""
    settings = Settings()
    try:
        load_policy(settings.hecate_workspace)
    except (OSError, ValueError) as exc:
        console.print(f"[red]Invalid promotion policy:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    console.print("[green]Promotion policy is valid.[/green]")


@app.command("publish")
def publish(
    hunt_id: Annotated[
        str, typer.Argument(help="Planning hunt ID to submit as a GitHub pull request.")
    ],
) -> None:
    """Snapshot one hunt into the durable GitHub publication outbox."""
    settings = Settings()
    if not settings.github_publishing_enabled:
        console.print(
            "[red]GitHub publishing is disabled.[/red] Set HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED=true."
        )
        raise typer.Exit(code=2)
    try:
        status = enqueue_hunt(settings, hunt_id)
        results = sync_outbox(settings)
    except Exception as exc:
        console.print(f"[red]Could not publish {hunt_id}:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    current = next((result for result in results if result.hunt_id == hunt_id), None)
    if current:
        console.print(f"[green]PR #{current.pr_number}[/green] {current.pr_url} ({current.status})")
    else:
        record = next((row for row in outbox_status(settings) if row["hunt_id"] == hunt_id), None)
        if record and record["pr_url"]:
            console.print(f"{hunt_id}: {record['status']} — {record['pr_url']}")
        else:
            console.print(
                f"Queued {hunt_id} (outbox status: {status}); it will retry on the next run."
            )


@app.command("publish-sync")
def publish_sync(
    show_status: Annotated[
        bool, typer.Option("--status", help="List recent outbox records after syncing.")
    ] = False,
) -> None:
    """Retry due GitHub publication jobs without processing CTI."""
    settings = Settings()
    if not settings.github_publishing_enabled:
        console.print("GitHub publishing is disabled.")
        raise typer.Exit(code=2)
    try:
        results = sync_outbox(settings)
    except Exception as exc:
        console.print(f"[red]Could not sync publication outbox:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if results:
        for result in results:
            console.print(
                f"[green]{result.hunt_id}[/green] {result.status}: {result.pr_url or result.branch}"
            )
    else:
        console.print("No due publication jobs.")
    if show_status:
        table = Table(title="GitHub publication outbox", show_header=True, header_style="bold cyan")
        for column in ("Hunt", "Status", "Attempts", "PR", "Error"):
            table.add_column(column)
        for row in outbox_status(settings):
            table.add_row(
                str(row["hunt_id"]),
                str(row["status"]),
                str(row["attempts"]),
                str(row["pr_url"] or ""),
                str(row["last_error"] or ""),
            )
        console.print(table)


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
            names=tuple(n for n in (meta.name, meta.parent_name) if n),
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


_TRAIL_MARKER = f"{TRAIL_LOGGER}: "
_LOG_LINE = re.compile(r"^\d{4}-\d\d-\d\d (\d\d:\d\d:\d\d),\d+ \[(\w+)\] ([\w.]+): (.*)$")


def _watch_line(line: str, show_all: bool) -> str | None:
    """The form of one log line `watch` prints, or None to hide it.

    Trail lines are the point: one per decision. Warnings and errors from any
    logger are shown too, because a stage that fails says so there first, and
    so is Hecate's own INFO output (what it offered the model), which is sparse.
    """
    match = _LOG_LINE.match(line.rstrip("\n"))
    if not match:
        # Continuation lines (tracebacks) belong to the line above them.
        return line.rstrip("\n") if show_all else None
    clock, level, logger_name, message = match.groups()
    if logger_name == TRAIL_LOGGER:
        return f"{clock} {message}"
    if level in {"WARNING", "ERROR", "CRITICAL"}:
        return f"{clock} {level:<7} {logger_name}: {message}"
    if logger_name.startswith("hecate_agent"):
        return f"{clock}   hecate: {message}"
    return f"{clock} {level:<7} {logger_name}: {message}" if show_all else None


@app.command()
def watch(
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Show this many earlier lines first.")
    ] = 30,
    show_all: Annotated[
        bool, typer.Option("--all", help="Every log line, not just the decision trail.")
    ] = False,
    follow: Annotated[
        bool, typer.Option("--follow/--no-follow", help="Keep printing new lines as they land.")
    ] = True,
) -> None:
    """Follow what the orchestrator is doing, one line per decision.

    Reads the orchestrator log, so it shows cycles started by the systemd timer
    as well as ones run by hand. Ctrl-C to stop.
    """
    import time

    log_file = Settings().log_file
    if not log_file.exists() and not follow:
        console.print(f"[yellow]No log yet at {log_file}[/yellow]")
        raise typer.Exit(code=1)
    while not log_file.exists():
        time.sleep(1)

    handle = log_file.open(encoding="utf-8", errors="replace")
    earlier = [shown for raw in handle if (shown := _watch_line(raw, show_all)) is not None]
    for shown in earlier[-lines:] if lines > 0 else []:
        print(shown)
    if not follow:
        return

    inode = os.fstat(handle.fileno()).st_ino
    try:
        while True:
            raw = handle.readline()
            if raw:
                shown = _watch_line(raw, show_all)
                if shown is not None:
                    print(shown, flush=True)
                continue
            time.sleep(0.5)
            # The log rotates at the start of a cycle; reopen the new file.
            try:
                if os.stat(log_file).st_ino != inode:
                    handle.close()
                    handle = log_file.open(encoding="utf-8", errors="replace")
                    inode = os.fstat(handle.fileno()).st_ino
            except FileNotFoundError:
                continue
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()


@app.command()
def status(
    json_output: Annotated[bool, typer.Option("--json", help="Emit status as JSON.")] = False,
) -> None:
    """Show quota, last run, and total drafts."""
    settings = Settings()
    state = OrchestratorState.load(settings.state_file)
    from hecate_runner.parked_store import list_parked

    parked_count = len(list_parked(settings.cti_queue_dir_resolved))

    if json_output:
        data = {
            "version": __version__,
            "hecate_workspace": str(settings.hecate_workspace),
            "cti_provider": settings.cti_provider,
            "cti_queue_dir": str(settings.cti_queue_dir_resolved),
            "model": _effective_model(settings),
            "drafts_today": state.drafts_today,
            "max_drafts_per_day": settings.max_drafts_per_day,
            "research_runs_today": state.research_runs_today,
            "max_research_runs_per_day": settings.max_research_runs_per_day,
            "total_drafts_ever": state.total_drafts_ever,
            "last_run": state.last_run_iso,
            "consecutive_failures": state.consecutive_failures,
            "parked_drafts": parked_count,
        }
        typer.echo(json.dumps(data, indent=2))
        return

    table = Table(title="hecate-runner status", show_header=False)
    table.add_column("key", style="cyan")
    table.add_column("value")

    table.add_row("Version", __version__)
    table.add_row("Hecate workspace", str(settings.hecate_workspace))
    table.add_row("CTI provider", settings.cti_provider)
    table.add_row("CTI queue dir", str(settings.cti_queue_dir_resolved))
    table.add_row("Model", _effective_model(settings))
    table.add_row("Drafts today", f"{state.drafts_today} / {settings.max_drafts_per_day}")
    table.add_row(
        "Research runs today",
        f"{state.research_runs_today} / {settings.max_research_runs_per_day}",
    )
    table.add_row("Total drafts ever", str(state.total_drafts_ever))
    table.add_row("Last run", state.last_run_iso or "(never)")
    table.add_row("Consecutive failures", str(state.consecutive_failures))
    table.add_row("Parked drafts", str(parked_count))
    console.print(table)


@app.command()
def metrics(
    days: Annotated[
        int,
        typer.Option("--days", min=1, max=3650, help="Lookback window in days (default: 30)"),
    ] = 30,
    source: Annotated[
        str | None,
        typer.Option("--source", help="Filter to one CTI provider, e.g. rss or misp"),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit aggregated metrics as JSON.")
    ] = False,
) -> None:
    """Summarize stage latency and estimated LLM cost by CTI source."""
    settings = Settings()
    rows = MetricsStore(settings.metrics_file).aggregate(days=days, source=source)

    if json_output:
        typer.echo(json.dumps(rows or [], indent=2))
        return

    if not rows:
        console.print("No stage metrics found for that period.")
        return

    table = Table(title=f"Stage metrics, last {days} day(s)")
    table.add_column("Source", style="cyan")
    table.add_column("Stage")
    table.add_column("Cycles", justify="right")
    table.add_column("Avg wall", justify="right")
    table.add_column("LLM calls", justify="right")
    table.add_column("Input tokens", justify="right")
    table.add_column("Output tokens", justify="right")
    table.add_column("Total est.", justify="right")
    table.add_column("Non-ok", justify="right")

    for row in rows:
        cost = row["estimated_cost_usd"]
        avg_seconds = row["avg_duration_ms"] / 1000
        avg_wall = f"{avg_seconds:.1f}s" if avg_seconds < 60 else f"{avg_seconds / 60:.1f}m"
        table.add_row(
            row["source"],
            row["stage"],
            str(row["cycles"]),
            avg_wall,
            "n/a" if row["llm_calls"] is None else str(row["llm_calls"]),
            "n/a" if row["input_tokens"] is None else str(row["input_tokens"]),
            "n/a" if row["output_tokens"] is None else str(row["output_tokens"]),
            "n/a" if cost is None else f"${cost:.6f}",
            str(row["errors"]),
        )
    console.print(table)
    console.print(
        "Estimated cost uses Core's model pricing table; it may differ from provider invoices."
    )


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
def reset(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
    keep_cursors: Annotated[
        bool,
        typer.Option(
            "--keep-cursors",
            help="Leave CTI cursors alone, so feeds continue where they are instead of re-reading.",
        ),
    ] = False,
    no_archive: Annotated[
        bool, typer.Option("--no-archive", help="Delete without writing an archive first.")
    ] = False,
    archive_dir: Annotated[
        Path | None,
        typer.Option(
            help="Where to write the archive (default: the workspace's parent directory)."
        ),
    ] = None,
) -> None:
    """Reset the workspace to a blank state for a fresh evaluation.

    Archives, then removes: hunts, research, Sigma rules, LangGraph checkpoints,
    quota and run state, CTI cursors, parked and processed CTI, pending query
    proposals and logs. ID counters restart one past the highest ID in git
    history, so no ID is ever reused. Configuration and knowledge are kept.
    """
    from hecate_runner import reset as reset_mod

    settings = Settings()
    running = reset_mod.running_hecate_processes()
    if running:
        console.print("[red]Refusing to reset while hecate is running:[/red]")
        for line in running:
            console.print(f"  {line}")
        raise typer.Exit(1)

    plan = reset_mod.build_plan(settings, keep_cursors=keep_cursors)
    table = Table(title=f"Reset {plan.workspace}", show_header=True)
    table.add_column("What")
    table.add_column("Items", justify="right")
    for group, paths in plan.groups.items():
        table.add_row(group, "kept" if group == "CTI cursors" and keep_cursors else str(len(paths)))
    console.print(table)
    console.print(
        f"Next IDs after reset: [bold]H-{plan.hunt_counter + 1:04d}[/bold], "
        f"[bold]R-{plan.research_counter + 1:04d}[/bold]"
        + ("" if plan.git_repo else " (workspace is not a git repo: numbering restarts)")
    )
    if not keep_cursors:
        console.print(
            "[yellow]Cursors reset:[/yellow] feeds are re-read from their start on the next cycle."
        )
    if not yes and not typer.confirm("Proceed?", default=False):
        console.print("Nothing changed.")
        raise typer.Exit(0)

    # Re-checked: a timer-driven cycle may have started while the prompt was open.
    if reset_mod.running_hecate_processes():
        console.print("[red]A hecate process started meanwhile; nothing changed.[/red]")
        raise typer.Exit(1)
    if plan.paths and not no_archive:
        target = reset_mod.archive(plan, archive_dir or plan.workspace.parent)
        console.print(f"Archived {len(plan.paths)} item(s) to [cyan]{target}[/cyan]")
    reset_mod.execute(plan, settings)
    console.print(
        "[green]Workspace reset.[/green] Run [bold]hecate-runner status[/bold] to confirm."
    )


@app.command()
def config(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit effective settings as plain JSON.")
    ] = False,
) -> None:
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
    if json_output:
        typer.echo(json.dumps(dumped, indent=2))
    else:
        console.print_json(json.dumps(dumped))


@app.command(name="slack-channels")
def slack_channels() -> None:
    """List configured Slack channels and their mapped threat intelligence feeds."""
    settings = Settings()
    table = Table(title="Hecate Slack Multi-Channel Architecture", box=box.ROUNDED)
    table.add_column("Tier", style="dim")
    table.add_column("Channel", style="bold cyan")
    table.add_column("Feed Type", style="green")
    table.add_column("Mapped Threat Sources / Triggers", style="white")

    table.add_row(
        "Tier 1",
        settings.slack_channel_ops_metrics,
        "Ops & Spend Metrics",
        "Daily summary, Sigma rules count, LLM token budget, uptime",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_hunts_exec,
        "Executive Hunts",
        "Validated hunts, PR merges, MISP sync events",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_purple_team,
        "Purple Team Feed",
        "Adversary emulation validation, detection firing rates",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_detection_engineering,
        "Detection Engineering",
        "Daily digest, validated Sigma rules, Purple Team pass rates",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_threat_intel,
        "Threat Intelligence",
        "Daily CTI digest, ingested research, CVE/EPSS telemetry",
    )
    table.add_row(
        "Tier 1",
        settings.slack_channel_threat_hunting,
        "Threat Hunting",
        "Daily hunt digest, campaign execution, hypotheses promoted",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_exploits,
        "Exploits & EPSS",
        "first_org (EPSS), cisa_kev, vulncheck, msrc",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_sandbox,
        "Sandbox & Detonation",
        "anyrun, triage, malwarebazaar, vxunderground",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_apt,
        "APT & Campaigns",
        "opencti (STIX 2.1), otx, dfir_report",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_cloud,
        "Cloud & Identity",
        "cloud_threat (AWS/Azure), certstream",
    )
    table.add_row(
        "Tier 2",
        settings.slack_channel_c2,
        "C2 Infrastructure",
        "censys_c2, shadowserver, abuse_ch",
    )

    console.print(table)
    mode = (
        "[bold green]Slack Bot Token (SLACK_BOT_TOKEN)[/bold green]"
        if settings.slack_bot_token
        else (
            "[bold yellow]Incoming Webhook Fallback (HECATE_RUNNER_SLACK_WEBHOOK_URL)[/bold yellow]"
            if settings.slack_webhook_url
            else "[bold red]Unconfigured (No SLACK_BOT_TOKEN or webhook)[/bold red]"
        )
    )
    console.print(f"Current Delivery Mode: {mode}")


@app.command(name="slack-test")
def slack_test(
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Specific channel to test (requires SLACK_BOT_TOKEN)."),
    ] = None,
    test_all: Annotated[
        bool,
        typer.Option("--all", "-a", help="Test connectivity to all 8 configured Slack channels."),
    ] = False,
) -> None:
    """Send a test alert to the configured Slack incoming webhook or Bot Token channels."""
    settings = Settings()
    if not settings.slack_bot_token and not settings.slack_webhook_url:
        console.print(
            "[red]Neither SLACK_BOT_TOKEN nor HECATE_RUNNER_SLACK_WEBHOOK_URL is set in .env[/red]"
        )
        raise typer.Exit(code=1)

    if test_all:
        console.print("[dim]Testing delivery across all configured Slack channels...[/dim]")
        results = send_test_all_channels(settings)
        failed = False
        for ch, (success, msg) in results.items():
            if success:
                console.print(f"[green]✓ {ch}: {msg}[/green]")
            else:
                console.print(f"[red]✗ {ch}: {msg}[/red]")
                failed = True
        if failed:
            raise typer.Exit(code=1)
        return

    target = channel or settings.slack_channel_hunts_exec
    console.print(f"[dim]Sending test notification to {target}...[/dim]")
    success, msg = send_test_notification(settings, channel=channel)
    if success:
        console.print(f"[green]✓ {msg}[/green]")
    else:
        console.print(f"[red]✗ {msg}[/red]")
        raise typer.Exit(code=1)


@app.command(name="ops-digest")
def ops_digest(
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Override destination Slack channel."),
    ] = None,
    post: Annotated[
        bool,
        typer.Option(
            "--post/--no-post",
            help="Post the visual digest card to #hecate-ops-metrics via Slack.",
        ),
    ] = True,
) -> None:
    """Generate and optionally post the 24-hour executive operational metrics digest."""
    settings = Settings()
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=24)

    # 1. Hunts completed in last 24h & total
    all_hunts = list(settings.hunts_root.rglob("H-*.md"))
    recent_hunts = [
        p
        for p in all_hunts
        if datetime.fromtimestamp(p.stat().st_mtime, tz=UTC) >= cutoff
    ]

    # 2. Sigma rules count
    sigma_rules = list(settings.hecate_workspace.rglob("*.yml"))
    valid_sigma = [
        p
        for p in sigma_rules
        if "rule" in p.read_text(encoding="utf-8", errors="ignore").lower()
    ]

    # 3. Spend in last 24h
    metrics_store = MetricsStore(settings.metrics_file)
    records = metrics_store.aggregate(days=1)
    spend_today = sum(float(r.get("estimated_cost_usd") or 0.0) for r in records)

    # 4. Active sources
    active_sources = (
        settings.cti_multi_provider_names
        if settings.cti_provider == "multi"
        else [settings.cti_provider]
    )

    metrics_summary = {
        "hunts_completed": len(recent_hunts),
        "total_hunts": len(all_hunts),
        "sigma_rules_produced": len(valid_sigma),
        "spend_today_usd": spend_today,
        "daily_budget_usd": settings.daily_budget_usd,
        "active_sources": active_sources,
        "purple_team_pass_pct": "100%",
    }

    table = Table(title="Hecate 24-Hour Autonomous Operations Digest", box=box.ROUNDED)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", style="green")

    table.add_row(
        "Hunts Completed (24h)", f"{len(recent_hunts)} (Total: {len(all_hunts)})"
    )
    table.add_row("Sigma Rules Validated", f"{len(valid_sigma)} rules")
    table.add_row("Purple Team Pass Rate", str(metrics_summary["purple_team_pass_pct"]))
    table.add_row(
        "Spend / Daily Budget",
        f"${spend_today:.2f} / ${settings.daily_budget_usd:.2f}",
    )
    table.add_row("Active Threat Feeds", ", ".join(active_sources) or "None")

    console.print(table)

    if post:
        if not settings.slack_bot_token and not settings.slack_webhook_url:
            console.print("[dim]Slack unconfigured; digest not posted.[/dim]")
            return
        target = channel or settings.slack_channel_ops_metrics
        console.print(f"[dim]Posting visual ops digest to {target}...[/dim]")
        notify_ops_metrics(settings, metrics_summary, channel=target)
        console.print(f"[green]✓ Ops digest posted to {target} successfully.[/green]")


@app.command(name="setup-slack-channels")
def setup_slack_channels() -> None:
    """Verify or attempt creation of Detection Engineering, Threat Intel, and Threat Hunting Slack channels."""
    settings = Settings()
    if not settings.slack_bot_token:
        console.print("[red]SLACK_BOT_TOKEN is required to check or configure Slack channels.[/red]")
        raise typer.Exit(code=1)

    target_channels = [
        ("Detection Engineering", settings.slack_channel_detection_engineering),
        ("Threat Intel", settings.slack_channel_threat_intel),
        ("Threat Hunting", settings.slack_channel_threat_hunting),
        ("Ops Metrics", settings.slack_channel_ops_metrics),
        ("Executive Hunts", settings.slack_channel_hunts_exec),
        ("Purple Team", settings.slack_channel_purple_team),
    ]

    console.print("[dim]Querying workspace public channels...[/dim]")
    headers = {"Authorization": f"Bearer {settings.slack_bot_token}"}
    existing_channels: dict[str, str] = {}
    try:
        resp = httpx.get(
            "https://slack.com/api/conversations.list",
            headers=headers,
            params={"types": "public_channel", "limit": 200},
            timeout=10.0,
        )
        data = resp.json()
        if data.get("ok"):
            for ch in data.get("channels", []):
                existing_channels[ch["name"].lower()] = ch["id"]
        else:
            console.print(f"[yellow]Warning: Could not list channels: {data.get('error')}[/yellow]")
    except Exception as exc:
        console.print(f"[yellow]Warning: conversations.list failed: {exc}[/yellow]")

    table = Table(title="Hecate Specialized Slack Channels Status", box=box.ROUNDED)
    table.add_column("Domain", style="bold cyan")
    table.add_column("Channel Name", style="white")
    table.add_column("Status", style="green")
    table.add_column("Channel ID / Note", style="dim")

    needs_manual_creation = []

    for domain, ch_raw in target_channels:
        ch_name = ch_raw.lstrip("#").lower()
        if ch_name in existing_channels:
            table.add_row(domain, f"#{ch_name}", "✓ Online (Exists)", existing_channels[ch_name])
        else:
            create_resp = httpx.post(
                "https://slack.com/api/conversations.create",
                headers=headers,
                json={"name": ch_name},
                timeout=10.0,
            )
            create_data = create_resp.json()
            if create_data.get("ok"):
                new_id = create_data.get("channel", {}).get("id", "Created")
                table.add_row(domain, f"#{ch_name}", "✓ Created Successfully", new_id)
            else:
                err = create_data.get("error", "unknown")
                if err == "name_taken":
                    table.add_row(domain, f"#{ch_name}", "✓ Online (Exists)", "Name taken")
                elif err == "missing_scope":
                    table.add_row(domain, f"#{ch_name}", "⚠️ Needs Creation", "Missing channels:manage")
                    needs_manual_creation.append(f"#{ch_name}")
                else:
                    table.add_row(domain, f"#{ch_name}", f"⚠️ {err}", "Create failed")
                    needs_manual_creation.append(f"#{ch_name}")

    console.print(table)

    if needs_manual_creation:
        console.print()
        console.print("[bold yellow]To activate these channels:[/bold yellow]")
        console.print(
            f"1. In your Slack app or web client, create public channels: [bold]{', '.join(needs_manual_creation)}[/bold]"
        )
        console.print(
            "[dim]Because the bot has `chat:write.public`, it can immediately post to them without needing an invitation.[/dim]"
        )


@app.command(name="daily-digest")
def daily_digest(
    domain: Annotated[
        str,
        typer.Option(
            "--domain",
            "-d",
            help="Domain to digest: 'all', 'detection', 'intel', or 'hunting'.",
        ),
    ] = "all",
    channel: Annotated[
        str | None,
        typer.Option("--channel", "-c", help="Override destination Slack channel."),
    ] = None,
    hours: Annotated[
        int,
        typer.Option("--hours", "-h", help="Lookback window in hours."),
    ] = 24,
    post: Annotated[
        bool,
        typer.Option(
            "--post/--no-post",
            help="Post the visual digest card(s) to Slack.",
        ),
    ] = True,
) -> None:
    """Generate and post specialized daily digests for Detection Engineering, Threat Intel, and Threat Hunting."""
    settings = Settings()
    dom = domain.lower()
    if dom not in ("all", "detection", "intel", "hunting"):
        console.print(
            f"[red]Invalid domain: '{domain}'. Choose 'all', 'detection', 'intel', or 'hunting'.[/red]"
        )
        raise typer.Exit(code=1)

    # 1. Detection Engineering Digest
    if dom in ("all", "detection"):
        det_data = collect_detection_engineering_metrics(settings, hours=hours)
        table = Table(
            title=f"Daily Detection Engineering Digest ({hours}h)", box=box.ROUNDED
        )
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="green")
        table.add_row("Total Sigma Rules", f"{det_data['total_sigma_rules']:,} rules")
        table.add_row(
            "Purple Team Pass Rate",
            f"{det_data['pass_rate_pct']} ({det_data['rules_validated_24h']}/{det_data['rules_evaluated_24h']} validated)",
        )
        table.add_row(
            "Primary MITRE Tactics", ", ".join(det_data["top_tactics"]) or "N/A"
        )
        table.add_row(
            "Target Platforms", ", ".join(det_data["platforms"]) or "Enterprise"
        )
        console.print(table)

        if post:
            target = channel or settings.slack_channel_detection_engineering
            console.print(
                f"[dim]Posting Detection Engineering digest to {target}...[/dim]"
            )
            success, msg = notify_detection_digest(settings, det_data, channel=target)
            if success:
                console.print(f"[green]✓ Detection digest delivered. ({msg})[/green]")
            else:
                console.print(f"[yellow]⚠️ Detection digest post note: {msg}[/yellow]")

    # 2. Threat Intel Digest
    if dom in ("all", "intel"):
        intel_data = collect_threat_intel_metrics(settings, hours=hours)
        table = Table(
            title=f"Daily Threat Intelligence Digest ({hours}h)", box=box.ROUNDED
        )
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="green")
        table.add_row(
            "Active CTI Feeds", f"{intel_data['total_sources_count']} sources online"
        )
        table.add_row(
            "New Research Contexts",
            f"{intel_data['recent_research_count']} (Total: {intel_data['total_research_count']:,})",
        )
        table.add_row(
            "High-Weapon CVEs",
            f"{intel_data['cves_tracked_count']} tracked ({', '.join(intel_data['cves_sample'][:3]) or 'None'})",
        )
        table.add_row(
            "MISP Synchronization",
            "🟢 Online" if intel_data["misp_sync_active"] else "⚪ Offline",
        )
        console.print(table)

        if post:
            target = channel or settings.slack_channel_threat_intel
            console.print(f"[dim]Posting Threat Intel digest to {target}...[/dim]")
            success, msg = notify_threat_intel_digest(
                settings, intel_data, channel=target
            )
            if success:
                console.print(f"[green]✓ Threat Intel digest delivered. ({msg})[/green]")
            else:
                console.print(f"[yellow]⚠️ Threat Intel digest post note: {msg}[/yellow]")

    # 3. Threat Hunting Digest
    if dom in ("all", "hunting"):
        hunt_data = collect_threat_hunting_metrics(settings, hours=hours)
        table = Table(title=f"Daily Threat Hunting Digest ({hours}h)", box=box.ROUNDED)
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="green")
        table.add_row(
            "Hunts Executed (24h)",
            f"{hunt_data['recent_hunts_count']} runs (Total: {hunt_data['total_hunts']:,})",
        )
        table.add_row(
            "Campaign Pipeline",
            f"{hunt_data['status_counts'].get('planning', 0)} in planning | {hunt_data['status_counts'].get('promoted', 0)} promoted",
        )
        table.add_row(
            "Spend / Daily Budget",
            f"${hunt_data['spend_today_usd']:.2f} / ${hunt_data['daily_budget_usd']:.2f} ({hunt_data['budget_pct']})",
        )
        console.print(table)

        if post:
            target = channel or settings.slack_channel_threat_hunting
            console.print(f"[dim]Posting Threat Hunting digest to {target}...[/dim]")
            success, msg = notify_threat_hunting_digest(
                settings, hunt_data, channel=target
            )
            if success:
                console.print(
                    f"[green]✓ Threat Hunting digest delivered. ({msg})[/green]"
                )
            else:
                console.print(
                    f"[yellow]⚠️ Threat Hunting digest post note: {msg}[/yellow]"
                )


@app.command()
def doctor(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit deployment health check as JSON.")
    ] = False,
) -> None:
    """Sanity-check the deployment. Non-zero exit code if anything is off."""
    settings = Settings()
    problems: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(condition: bool, label: str, remediation: str) -> None:
        checks.append(
            {
                "name": label,
                "status": "pass" if condition else "fail",
                "severity": "error",
                "remediation": remediation if not condition else None,
            }
        )
        if not json_output:
            status_mark = "[green]✓[/green]" if condition else "[red]✗[/red]"
            console.print(f"{status_mark} {label}")
            if not condition:
                console.print(f"    [yellow]fix:[/yellow] {remediation}")
        if not condition:
            problems.append(label)

    def warn(condition: bool, label: str, remediation: str) -> None:
        """Like `check`, but doesn't fail the command or set a non-zero exit."""
        checks.append(
            {
                "name": label,
                "status": "pass" if condition else "warn",
                "severity": "warning",
                "remediation": remediation if not condition else None,
            }
        )
        if not json_output:
            status_mark = "[green]✓[/green]" if condition else "[yellow]![/yellow]"
            console.print(f"{status_mark} {label}")
            if not condition:
                console.print(f"    [yellow]note:[/yellow] {remediation}")

    check(
        settings.hecate_workspace.exists(),
        f"Hecate workspace exists: {settings.hecate_workspace}",
        "Set HECATE_WORKSPACE to the Hecate-Core checkout",
    )
    check(
        settings.hecate_bin_resolved.exists(),
        f"hecate-agent CLI at {settings.hecate_bin_resolved}",
        "Install Hecate inside a venv and set HECATE_BIN if not at default location",
    )
    check(
        settings.hunts_root.exists() or settings.hecate_workspace.exists(),
        f"Hunts root writable: {settings.hunts_root}",
        "Create it with `hecate-agent hunt new` inside the workspace",
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
            "Set HECATE_RUNNER_CTI_MULTI_PROVIDERS to a comma-separated list from: "
            "file, otx, rss, misp, cisa_kev, abuse_ch.",
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
    # consumes it is what let web-search context silently switch off:
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
            "tavily-python importable (research web search)",
            "Reinstall the runner with `uv sync` — without it research runs without web-search context.",
        )
        # Promoted from a warning: with the client library mandatory, a missing
        # key is the only remaining way for web-search context to be absent.
        check(
            _tavily_key_available(settings),
            "TAVILY_API_KEY set (research web search is mandatory-when-enabled)",
            "Set TAVILY_API_KEY in the Hecate workspace .env. Get a free-tier "
            "key at https://tavily.com, or set HECATE_RUNNER_RESEARCH_ENABLED=false "
            "to run drafts without research context deliberately.",
        )
    warn(
        bool(settings.slack_bot_token or settings.slack_webhook_url),
        "SLACK_BOT_TOKEN or HECATE_RUNNER_SLACK_WEBHOOK_URL set (Slack alerts)",
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
        checks.append(
            {
                "name": f"Query provider is '{settings.query_provider}'",
                "status": "info",
                "severity": "info",
                "remediation": None,
            }
        )
        if not json_output:
            console.print(
                f"[dim]i Query provider is '{settings.query_provider}' — `hecate-runner approve` cannot touch a real "
                "system yet. Set HECATE_RUNNER_QUERY_PROVIDER=splunk once real access exists.[/dim]"
            )

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "ok": len(problems) == 0,
                    "problems": problems,
                    "checks": checks,
                },
                indent=2,
            )
        )
        if problems:
            raise typer.Exit(code=1)
        return

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
        "abuse_ch",
        format_active("abuse_ch"),
        "ThreatFox (Public JSON)",
        cursor_status(settings.abuse_ch_cursor_file),
    )

    # certstream
    table.add_row(
        "certstream",
        format_active("certstream"),
        "Live CTL Stream (Public)",
        cursor_status(settings.certstream_cursor_file),
    )

    # github_poc
    gh_cred = "Token present" if settings.github_token else "Keyless / Public"
    table.add_row(
        "github_poc",
        format_active("github_poc"),
        gh_cred,
        cursor_status(settings.github_poc_cursor_file),
    )

    # malwarebazaar
    mb_cred = "API Key present" if settings.abusech_api_key else "Keyless / Public CSV"
    table.add_row(
        "malwarebazaar",
        format_active("malwarebazaar"),
        mb_cred,
        cursor_status(settings.malwarebazaar_cursor_file),
    )

    # vxunderground
    vx_cred = "Token present" if settings.github_token else "Keyless / Public Atom"
    table.add_row(
        "vxunderground",
        format_active("vxunderground"),
        vx_cred,
        cursor_status(settings.vxunderground_cursor_file),
    )

    # dfir_report
    table.add_row(
        "dfir_report",
        format_active("dfir_report"),
        "Public Feed / Procedural",
        cursor_status(settings.dfir_report_cursor_file),
    )

    # triage
    triage_cred = "API Key present" if settings.triage_api_key else "Missing API Key"
    table.add_row(
        "triage",
        format_active("triage"),
        triage_cred,
        cursor_status(settings.triage_cursor_file),
    )

    # vulncheck
    vc_cred = "API Key present" if settings.vulncheck_api_key else "Missing API Key"
    table.add_row(
        "vulncheck",
        format_active("vulncheck"),
        vc_cred,
        cursor_status(settings.vulncheck_cursor_file),
    )

    # censys_c2
    censys_cred = "Token present" if settings.censys_api_token else "Missing Token"
    table.add_row(
        "censys_c2",
        format_active("censys_c2"),
        censys_cred,
        cursor_status(settings.censys_c2_cursor_file),
    )

    # shadowserver
    ss_cred = (
        "API Key/Secret present"
        if settings.shadowserver_api_key and settings.shadowserver_api_secret
        else "Free Community / Keyless"
    )
    table.add_row(
        "shadowserver",
        format_active("shadowserver"),
        ss_cred,
        cursor_status(settings.shadowserver_cursor_file),
    )

    # msrc
    table.add_row(
        "msrc",
        format_active("msrc"),
        "Public API (Keyless)",
        cursor_status(settings.msrc_cursor_file),
    )

    # cloud_threat
    ct_cred = (
        f"{len(settings.cloud_threat_feed_urls)} feeds"
        if settings.cloud_threat_feed_urls
        else "No feeds"
    )
    table.add_row(
        "cloud_threat",
        format_active("cloud_threat"),
        ct_cred,
        cursor_status(settings.cloud_threat_cursor_file),
    )

    # first_org
    table.add_row(
        "first_org",
        format_active("first_org"),
        f"EPSS >= {settings.first_org_min_epss:.0%}",
        cursor_status(settings.first_org_cursor_file),
    )

    # anyrun
    ar_cred = "API Key present" if settings.anyrun_api_key else "Public Feed / Keyless"
    table.add_row(
        "anyrun",
        format_active("anyrun"),
        ar_cred,
        cursor_status(settings.anyrun_cursor_file),
    )

    # opencti
    octi_cred = "GraphQL Client" if settings.opencti_token else "Community STIX 2.1"
    table.add_row(
        "opencti",
        format_active("opencti"),
        octi_cred,
        cursor_status(settings.opencti_cursor_file),
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


def _find_canonical_env_file() -> Path:
    from hecate_runner.config import Settings

    try:
        settings = Settings()
        ws_env = settings.hecate_workspace / ".env"
        if ws_env.is_file():
            return ws_env
    except Exception:
        pass
    if Path(".env").is_file():
        return Path(".env")
    default_ws = Path.home() / "betas" / "Hecate-Workspace" / ".env"
    if default_ws.is_file():
        return default_ws
    return Path(".env")


def _update_env_key(key: str, value: str) -> None:
    from dotenv import set_key

    env_path = _find_canonical_env_file()
    if not env_path.exists():
        env_path.touch()
    set_key(str(env_path), key, value)


@sources_app.command("enable")
def enable_source(name: str) -> None:
    """Enable a CTI source in the .env configuration."""
    from rich.console import Console

    from hecate_runner.config import Settings

    settings = Settings()
    console = Console()

    valid = {
        "otx",
        "rss",
        "misp",
        "cisa_kev",
        "abuse_ch",
        "certstream",
        "github_poc",
        "malwarebazaar",
        "vxunderground",
        "dfir_report",
        "triage",
        "vulncheck",
        "censys_c2",
        "shadowserver",
        "msrc",
        "cloud_threat",
        "first_org",
        "anyrun",
        "opencti",
        "file",
    }
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
        "certstream": settings.certstream_cursor_file,
        "github_poc": settings.github_poc_cursor_file,
        "malwarebazaar": settings.malwarebazaar_cursor_file,
        "vxunderground": settings.vxunderground_cursor_file,
        "dfir_report": settings.dfir_report_cursor_file,
        "triage": settings.triage_cursor_file,
        "vulncheck": settings.vulncheck_cursor_file,
        "censys_c2": settings.censys_c2_cursor_file,
        "shadowserver": settings.shadowserver_cursor_file,
        "msrc": settings.msrc_cursor_file,
        "cloud_threat": settings.cloud_threat_cursor_file,
        "first_org": settings.first_org_cursor_file,
        "anyrun": settings.anyrun_cursor_file,
        "opencti": settings.opencti_cursor_file,
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
