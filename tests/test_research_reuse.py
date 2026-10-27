"""Tests for research document reuse in the orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.metrics import LLMUsage
from hecate_runner.orchestrator import Orchestrator


class TestResearchReuse:
    def test_recent_research_is_reused_avoiding_research_new(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        research_dir = workspace / "research"
        research_dir.mkdir()

        # Create an existing research file for "Lumma Stealer"
        existing_research = research_dir / "R-0100.md"
        existing_research.write_text(
            """---
research_id: R-0100
topic: Lumma Stealer
mitre_techniques:
  - T1059.001
status: completed
depth: basic
linked_hunts:
  - H-0010
grounding: web_and_local
created_date: 2026-10-25T12:00:00+00:00
---

# R-0100: Lumma Stealer Analysis
Detailed analysis of Lumma Stealer loader and C2.
"""
        )

        settings = Settings(
            hecate_workspace=workspace,
            research_enabled=True,
            research_reuse_enabled=True,
            research_reuse_max_age_days=7,
            sigma_generation_enabled=False,
            purple_team_validation_enabled=False,
        )

        mock_provider = MagicMock()
        item = CTIItem(
            source="test-1",
            content="Report details recent Lumma Stealer activity delivering payload via PowerShell T1059.001.\n\nDescription: Detailed analysis of adversary techniques.",
            title="Lumma Stealer Threat Advisory",
        )
        mock_provider.next_item.return_value = item

        mock_client = MagicMock()
        mock_client.workspace = workspace
        # If research_new is called, fail the test
        mock_client.research_new.side_effect = AssertionError(
            "research_new should not be called when reused!"
        )

        # hypothesis_generator should receive the reused research_id
        mock_client.hypothesis_generator.return_value = HypothesisResult(
            hypothesis="Adversaries execute Lumma Stealer via PowerShell",
            techniques=["T1059.001"],
            data_sources=["process_creation"],
            observables=["powershell.exe -enc"],
            location="Windows endpoints",
            usage=LLMUsage(),
        )

        orch = Orchestrator(
            settings=settings,
            hecate=mock_client,
            cti_provider=mock_provider,
        )

        result = orch.run_once(dry_run=False)
        assert result.ok
        assert result.research_id == "R-0100"
