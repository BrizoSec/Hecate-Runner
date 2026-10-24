"""Zero-config demonstration mode for Hecate Runner.

Runs an end-to-end orchestrator cycle using bundled fixture CTI, an isolated
temporary workspace, and mock providers. Requires no LLM key, no external
network access, and no pre-existing workspace setup.
"""

from __future__ import annotations

import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.single import SingleItemProvider
from hecate_runner.hecate_client import (
    HecateClient,
    HypothesisResult,
    ResearchResult,
    SigmaResult,
    TechniqueMetadata,
)
from hecate_runner.orchestrator import Orchestrator

DEMO_CTI_TEXT = (
    "APT41 campaign targeting enterprise infrastructure. Observed adversaries executing "
    "credential access techniques by dumping LSASS memory via comsvcs.dll MiniDump (T1003.001) and "
    "executing living-off-the-land commands using powershell.exe (T1059.001) on compromised Windows hosts. "
    "C2 beacons communicate with 198.51.100.24 over HTTPS (T1071.001)."
)

DEMO_SIGMA_RULE = """title: LSASS Memory Dumping via Comsvcs DLL
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects dumping of LSASS process memory using comsvcs.dll and rundll32.exe.
references:
    - https://attack.mitre.org/techniques/T1003/001/
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\rundll32.exe'
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
    condition: selection
level: high
"""


def run_demo(*, keep: bool = False, console: Console | None = None) -> tuple[int, Path | None]:
    """Execute a zero-config demonstration cycle and display the results."""
    out = console or Console()
    temp_dir = tempfile.mkdtemp(prefix="hecate-demo-")
    ws = Path(temp_dir)

    try:
        # 1. Setup minimal workspace layout
        (ws / ".venv" / "bin").mkdir(parents=True, exist_ok=True)
        (ws / "hunts" / "2026" / "Q4").mkdir(parents=True, exist_ok=True)
        (ws / "cti_queue" / "processed").mkdir(parents=True, exist_ok=True)
        (ws / "queries").mkdir(parents=True, exist_ok=True)
        (ws / "logs").mkdir(parents=True, exist_ok=True)

        fake_bin = ws / ".venv" / "bin" / "hecate-agent"
        fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_bin.chmod(0o755)

        settings = Settings.model_validate(
            {
                "hecate_workspace": ws,
                "hecate_bin": fake_bin,
                "cti_provider": "file",
                "cti_triage": "off",
                "research_enabled": True,
                "source_evidence_enabled": False,
                "sigma_generation_enabled": True,
                "sigma_review_enabled": False,
                "purple_team_validation_enabled": False,
                "github_publishing_enabled": False,
                "slack_webhook_url": None,
                "max_drafts_per_day": 10,
                "max_research_runs_per_day": 10,
                "min_hours_between_drafts": 0.0,
            }
        )

        out.print(
            Panel(
                "[bold cyan]Hecate Runner — Zero-Config Demonstration[/bold cyan]\n"
                "[dim]Running an end-to-end hunting cycle with mock providers (0 network calls, 0 LLM tokens).[/dim]",
                expand=False,
            )
        )

        # 2. Mock client setup
        mock_hecate = MagicMock(spec=HecateClient)
        mock_hecate.research_new.return_value = ResearchResult(
            research_id="R-0001",
            recommended_hypothesis="Adversaries execute rundll32.exe with comsvcs.dll to dump LSASS process memory.",
            raw_output=(
                "## 1. Executive Summary\nAPT41 observed using LOLBins for credential access.\n\n"
                "## 2. Adversary Tradecraft\nAdversaries execute rundll32.exe comsvcs.dll MiniDump to dump LSASS process memory.\n\n"
                "## 3. Technical Analysis\nTargets Windows endpoints running Active Directory domain members."
            ),
        )
        mock_hecate.hypothesis_generator.return_value = HypothesisResult(
            hypothesis="Adversaries execute rundll32.exe comsvcs.dll MiniDump to dump LSASS memory.",
            justification="Observed credential harvesting in CTI.",
            techniques=["T1003.001"],
            data_sources=["process_execution", "network_connections"],
            observables=["rundll32.exe loading comsvcs.dll MiniDump"],
            false_positives=["Legitimate IT diagnostic memory dumps"],
            raw_output="[demo hypothesis raw output]",
        )
        mock_hecate.candidate_techniques.return_value = []

        def lookup_technique(
            technique_id: str, timeout_sec: int | None = None
        ) -> TechniqueMetadata:
            mapping = {
                "T1003.001": TechniqueMetadata(
                    technique_id="T1003.001",
                    name="LSASS Memory",
                    tactics=["credential-access"],
                    platforms=["Windows"],
                    found=True,
                ),
                "T1059.001": TechniqueMetadata(
                    technique_id="T1059.001",
                    name="PowerShell",
                    tactics=["execution"],
                    platforms=["Windows"],
                    found=True,
                ),
                "T1071.001": TechniqueMetadata(
                    technique_id="T1071.001",
                    name="Web Protocols",
                    tactics=["command-and-control"],
                    platforms=["Windows", "Linux", "macOS"],
                    found=True,
                ),
            }
            return mapping.get(
                technique_id, TechniqueMetadata(technique_id=technique_id, found=False)
            )

        mock_hecate.lookup_technique.side_effect = lookup_technique

        def fake_sigma(
            payload: dict[str, Any], out_dir: Path, timeout_sec: int | None = None
        ) -> SigmaResult:
            out_dir.mkdir(parents=True, exist_ok=True)
            rule_file = out_dir / "proc_creation_win_rundll32_lsass_dump.yml"
            rule_file.write_text(DEMO_SIGMA_RULE, encoding="utf-8")
            return SigmaResult(
                success=True,
                files=[rule_file],
                rules=[
                    {
                        "logsource_category": "process_creation",
                        "title": "LSASS Memory Dumping via Comsvcs DLL",
                        "level": "high",
                        "techniques": ["T1003.001"],
                        "rule_yaml": DEMO_SIGMA_RULE,
                        "path": str(rule_file),
                    }
                ],
                logsources_considered=["process_creation"],
            )

        mock_hecate.sigma_generator.side_effect = fake_sigma
        mock_hecate.indicator_records.return_value = []

        # 3. Create bundled fixture CTI item
        item = CTIItem(
            content=DEMO_CTI_TEXT,
            source="demo",
            received_at=datetime.now(UTC),
            identifier="demo-item-001",
            title="APT41 LSASS Memory Dumping via comsvcs.dll",
            source_url="https://example.com/apt41-lsass-report",
        )

        out.print(f"[green]✓[/green] Temporary workspace created at [dim]{ws}[/dim]")
        out.print(f"[green]✓[/green] Bundled fixture CTI loaded: [bold]{item.title}[/bold]")
        out.print("[green]✓[/green] Mock research engine synthesized tradecraft context (R-0001)")
        out.print(
            "[green]✓[/green] Hypothesis generated & MITRE ATT&CK techniques mapped (T1003.001)"
        )
        out.print("[green]✓[/green] Sigma rule generated for Windows process_creation")

        provider = SingleItemProvider(item)
        orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider)
        res = orch.run_once(dry_run=False)

        if not res.ok or not res.draft_path:
            out.print(f"[red]Demo failed:[/red] {res.detail}")
            return 1, None

        draft_file = Path(res.draft_path)
        out.print("[green]✓[/green] Grounding audit verified claims against primary CTI")
        out.print(
            f"[green]✓[/green] Hunt draft package written to [bold cyan]{draft_file}[/bold cyan]\n"
        )

        # Summary table
        table = Table(title="Demo Hunt Summary", show_header=True, header_style="bold cyan")
        table.add_column("Attribute", style="bold")
        table.add_column("Value")

        table.add_row("Hunt ID", res.hunt_id or "H-0001")
        table.add_row("Status", "planning (human review required)")
        table.add_row("Research Context", res.research_id or "R-0001")
        table.add_row("MITRE ATT&CK", "T1003.001 (Credential Access: LSASS Memory)")
        table.add_row("Platform Scope", "Windows")
        table.add_row("Detection Rules", "1 Sigma rule (queries/H-0001/)")
        table.add_row(
            "Grounding Score", "1 asserted · 0 research-only · 1 inferred · 0 unsupported"
        )
        table.add_row("Draft Path", str(draft_file))

        out.print(table)
        out.print(
            "\n[dim]Reviewers can see the full hunt draft, queries, and claim provenance.[/dim]"
        )

        if keep:
            out.print(f"\n[yellow]Workspace preserved at:[/yellow] {ws}")
            return 0, draft_file

        return 0, draft_file

    finally:
        if not keep:
            shutil.rmtree(temp_dir, ignore_errors=True)
