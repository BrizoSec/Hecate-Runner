"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.hecate_client import HecateClient, HypothesisResult, ResearchResult


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A fake Hecate workspace with the standard directory layout."""
    ws = tmp_path / "hecate"
    (ws / ".venv" / "bin").mkdir(parents=True)
    (ws / "hunts" / "2026" / "Q3").mkdir(parents=True)
    (ws / "cti_queue" / "processed").mkdir(parents=True)
    (ws / "logs").mkdir()
    # Fake hecate-agent binary — an executable no-op
    bin_path = ws / ".venv" / "bin" / "hecate-agent"
    bin_path.write_text("#!/bin/sh\nexit 0\n")
    bin_path.chmod(0o755)
    return ws


@pytest.fixture
def settings(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Settings pointing at the fake workspace."""
    # Wipe any leaked env vars so tests are deterministic
    for var in [
        "HECATE_WORKSPACE",
        "HECATE_BIN",
        "HECATE_RUNNER_MAX_DRAFTS_PER_DAY",
        "HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY",
        "HECATE_RUNNER_LLM_TIMEOUT_SEC",
        "HECATE_RUNNER_CTI_PROVIDER",
        "HECATE_RUNNER_CTI_MULTI_PROVIDERS",
        "HECATE_RUNNER_LOG_LEVEL",
        "HECATE_RUNNER_CTI_QUEUE_DIR",
        "OTX_API_KEY",
        "HECATE_RUNNER_OTX_BASE_URL",
        "HECATE_RUNNER_OTX_PAGE_LIMIT",
        "HECATE_RUNNER_OTX_MAX_PULSE_AGE_DAYS",
        "HECATE_RUNNER_OTX_REQUEST_TIMEOUT_SEC",
        "HECATE_RUNNER_RSS_FEED_URLS",
        "HECATE_RUNNER_RSS_MAX_ENTRY_AGE_DAYS",
        "HECATE_RUNNER_RSS_REQUEST_TIMEOUT_SEC",
        "MISP_BASE_URL",
        "MISP_API_KEY",
        "HECATE_RUNNER_MISP_VERIFY_SSL",
        "HECATE_RUNNER_MISP_MAX_EVENT_AGE_DAYS",
        "HECATE_RUNNER_MISP_PAGE_LIMIT",
        "HECATE_RUNNER_MISP_REQUEST_TIMEOUT_SEC",
    ]:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "4")

    yield Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def otx_settings(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Settings with an OTX API key set, for otx CTI provider tests."""
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def sample_otx_pulse() -> dict[str, Any]:
    recent = (datetime.now(UTC) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return {
        "id": "pulse-1",
        "name": "APT41 credential access campaign",
        "adversary": "APT41",
        "tags": ["apt41", "china"],
        "description": "Observed dumping LSASS via comsvcs.dll on compromised hosts.",
        "created": recent,
        "modified": recent,
        "TLP": "white",
        "public": 1,
        "attack_ids": [{"id": "T1003.001", "name": "LSASS Memory"}],
        "indicators": [
            {"type": "FileHash-SHA256", "indicator": "a" * 64},
            {"type": "IPv4", "indicator": "1.2.3.4"},
        ],
        "references": ["https://example.com/report"],
    }


@pytest.fixture
def sample_hypothesis() -> HypothesisResult:
    return HypothesisResult(
        hypothesis="Adversaries dump LSASS memory via comsvcs.dll MiniDump.",
        justification="Common post-compromise credential access technique.",
        techniques=["T1003.001"],
        data_sources=["CrowdStrike", "Sysmon"],
        observables=[
            "rundll32.exe loading comsvcs.dll",
            "process access to lsass.exe with PROCESS_VM_READ",
        ],
        false_positives=["Legitimate EDR agent scanning"],
        raw_output="[fake raw output]",
    )


@pytest.fixture
def sample_research_result() -> ResearchResult:
    return ResearchResult(
        research_id="R-0001",
        recommended_hypothesis="Adversaries dump LSASS memory via comsvcs.dll MiniDump.",
        raw_output="[fake raw output]",
    )


@pytest.fixture
def file_queue_with_cti(workspace: Path) -> FileQueueProvider:
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "APT actor X observed dumping LSASS via comsvcs.dll on Windows endpoints."
    )
    return provider


@pytest.fixture
def hecate_client(workspace: Path) -> HecateClient:
    return HecateClient(
        hecate_bin=workspace / ".venv" / "bin" / "hecate-agent",
        workspace=workspace,
        env_overrides={"HECATE_LLM_PROVIDER": "ollama"},
    )
