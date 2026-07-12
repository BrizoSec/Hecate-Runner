"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from sec7669.athf_client import AthfClient, HypothesisResult, ResearchResult
from sec7669.config import Settings
from sec7669.cti import FileQueueProvider


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A fake ATHF workspace with the standard directory layout."""
    ws = tmp_path / "athf"
    (ws / ".venv" / "bin").mkdir(parents=True)
    (ws / "hunts" / "production" / "2026" / "Q3").mkdir(parents=True)
    (ws / "cti_queue" / "processed").mkdir(parents=True)
    (ws / "logs").mkdir()
    # Fake athf binary — an executable no-op
    bin_path = ws / ".venv" / "bin" / "athf"
    bin_path.write_text("#!/bin/sh\nexit 0\n")
    bin_path.chmod(0o755)
    return ws


@pytest.fixture
def settings(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Settings pointing at the fake workspace."""
    # Wipe any leaked env vars so tests are deterministic
    for var in [
        "ATHF_WORKSPACE",
        "ATHF_BIN",
        "SEC7669_MAX_DRAFTS_PER_DAY",
        "SEC7669_LLM_TIMEOUT_SEC",
        "SEC7669_CTI_PROVIDER",
        "SEC7669_LOG_LEVEL",
        "SEC7669_CTI_QUEUE_DIR",
        "OTX_API_KEY",
        "SEC7669_OTX_BASE_URL",
        "SEC7669_OTX_PAGE_LIMIT",
        "SEC7669_OTX_MAX_PULSE_AGE_DAYS",
        "SEC7669_OTX_REQUEST_TIMEOUT_SEC",
        "SEC7669_RSS_FEED_URLS",
        "SEC7669_RSS_MAX_ENTRY_AGE_DAYS",
        "SEC7669_RSS_REQUEST_TIMEOUT_SEC",
    ]:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("ATHF_WORKSPACE", str(workspace))
    monkeypatch.setenv("SEC7669_MAX_DRAFTS_PER_DAY", "4")

    yield Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def otx_settings(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Settings with an OTX API key set, for otx CTI provider tests."""
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    return Settings(_env_file=None)  # type: ignore[call-arg]


@pytest.fixture
def sample_otx_pulse() -> dict[str, Any]:
    return {
        "id": "pulse-1",
        "name": "APT41 credential access campaign",
        "adversary": "APT41",
        "tags": ["apt41", "china"],
        "description": "Observed dumping LSASS via comsvcs.dll on compromised hosts.",
        "created": "2026-07-01T00:00:00.000000",
        "modified": "2026-07-01T00:00:00.000000",
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
def athf_client(workspace: Path) -> AthfClient:
    return AthfClient(
        athf_bin=workspace / ".venv" / "bin" / "athf",
        workspace=workspace,
        env_overrides={"ATHF_LLM_PROVIDER": "ollama"},
    )
