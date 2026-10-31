"""Shared test fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.github_publisher import GitHubAppClient
from hecate_runner.hecate_client import (
    HecateClient,
    HypothesisResult,
    ResearchResult,
    SigmaResult,
    TechniqueMetadata,
)


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


_ENV_VARS_TO_ISOLATE = (
    "HECATE_WORKSPACE",
    "HECATE_BIN",
    "HECATE_LLM_PROVIDER",
    "HECATE_LLM_MODEL",
    "HECATE_RUNNER_MAX_DRAFTS_PER_DAY",
    "HECATE_RUNNER_MAX_RESEARCH_RUNS_PER_DAY",
    "HECATE_RUNNER_MIN_HOURS_BETWEEN_DRAFTS",
    "HECATE_RUNNER_LLM_TIMEOUT_SEC",
    "HECATE_RUNNER_CTI_PROVIDER",
    "HECATE_RUNNER_CTI_MULTI_PROVIDERS",
    "HECATE_RUNNER_LOG_LEVEL",
    "HECATE_RUNNER_CTI_QUEUE_DIR",
    "HECATE_RUNNER_SLACK_WEBHOOK_URL",
    "SLACK_WEBHOOK_URL",
    "HECATE_RUNNER_SLACK_BOT_TOKEN",
    "SLACK_BOT_TOKEN",
    "HECATE_RUNNER_SLACK_CHANNEL_OPS_METRICS",
    "HECATE_RUNNER_SLACK_CHANNEL_HUNTS_EXEC",
    "HECATE_RUNNER_SLACK_CHANNEL_PURPLE_FEED",
    "HECATE_RUNNER_SLACK_CHANNEL_EXPLOITS",
    "HECATE_RUNNER_SLACK_CHANNEL_SANDBOX",
    "HECATE_RUNNER_SLACK_CHANNEL_APT",
    "HECATE_RUNNER_SLACK_CHANNEL_CLOUD",
    "HECATE_RUNNER_SLACK_CHANNEL_C2",
    "HECATE_RUNNER_SLACK_CHANNEL_DETECTION_ENGINEERING",
    "SLACK_CHANNEL_DETECTION_ENGINEERING",
    "HECATE_RUNNER_SLACK_CHANNEL_THREAT_INTEL",
    "SLACK_CHANNEL_THREAT_INTEL",
    "HECATE_RUNNER_SLACK_CHANNEL_THREAT_HUNTING",
    "SLACK_CHANNEL_THREAT_HUNTING",
    "OTX_API_KEY",
    "HECATE_RUNNER_OTX_BASE_URL",
    "HECATE_RUNNER_OTX_PAGE_LIMIT",
    "HECATE_RUNNER_OTX_MAX_PULSE_AGE_DAYS",
    "HECATE_RUNNER_OTX_REQUEST_TIMEOUT_SEC",
    "HECATE_RUNNER_RSS_FEED_URLS",
    "HECATE_RUNNER_RSS_MAX_ENTRY_AGE_DAYS",
    "HECATE_RUNNER_RSS_REQUEST_TIMEOUT_SEC",
    "MISP_BASE_URL",
    "MISP_OUTPUT_API_KEY",
    "HECATE_RUNNER_MISP_PUBLISHING_ENABLED",
    "GITHUB_TOKEN",
    "HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED",
    "HECATE_RUNNER_GITHUB_APP_ID",
    "HECATE_RUNNER_GITHUB_INSTALLATION_ID",
    "HECATE_RUNNER_GITHUB_APP_SLUG",
    "HECATE_RUNNER_GITHUB_APP_PRIVATE_KEY_PATH",
    "HECATE_RUNNER_GITHUB_PUBLISHING_REPOSITORY",
    "HECATE_RUNNER_GITHUB_PUBLISHING_BASE_BRANCH",
    "HECATE_RUNNER_GITHUB_PUBLISHING_POLICY_PATH",
    "HECATE_RUNNER_GITHUB_PUBLISHING_OUTBOX_PATH",
    "MISP_API_KEY",
    "HECATE_RUNNER_MISP_VERIFY_SSL",
    "HECATE_RUNNER_MISP_MAX_EVENT_AGE_DAYS",
    "HECATE_RUNNER_MISP_PAGE_LIMIT",
    "HECATE_RUNNER_MISP_REQUEST_TIMEOUT_SEC",
    "GREYNOISE_API_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_TOKEN",
    "ABUSECH_API_KEY",
    "VT_API_KEY",
    "TAVILY_API_KEY",
    "OPENCTI_API_KEY",
    "ANYRUN_API_KEY",
    "FIRST_ORG_API_KEY",
)


@pytest.fixture(autouse=True)
def _never_the_live_workspace(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Point every test at a throwaway workspace unless it sets its own.

    Settings() falls back to the real Hecate workspace when HECATE_WORKSPACE is
    unset. A test that built its own Settings without the `settings` fixture
    ran a cycle against it: it appended rows to the live stage metrics, emptied
    the live call log and rewrote the orchestrator state.
    """
    for var in _ENV_VARS_TO_ISOLATE:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "false")
    monkeypatch.setenv("HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED", "false")
    monkeypatch.setenv("HECATE_BAS_ENABLED", "false")
    monkeypatch.setenv("HECATE_BAS_AUTO_EXECUTE_LIVE", "false")
    monkeypatch.setenv("HECATE_BAS_MODE", "mock")
    monkeypatch.setenv("HECATE_BAS_AUTO_TECHNIQUES", "")
    monkeypatch.setenv("HECATE_WORKSPACE", str(tmp_path_factory.mktemp("unset-workspace")))

    def reject_github_request(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("Tests must mock GitHub publisher requests before calling the API")

    monkeypatch.setattr(GitHubAppClient, "_request", reject_github_request)


@pytest.fixture
def settings(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    """Settings pointing at the fake workspace."""
    # Wipe any leaked env vars so tests are deterministic
    for var in _ENV_VARS_TO_ISOLATE:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("HECATE_RUNNER_MISP_PUBLISHING_ENABLED", "false")
    monkeypatch.setenv("HECATE_RUNNER_GITHUB_PUBLISHING_ENABLED", "false")
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    monkeypatch.setenv("HECATE_RUNNER_MAX_DRAFTS_PER_DAY", "4")
    monkeypatch.setenv("HECATE_RUNNER_MIN_HOURS_BETWEEN_DRAFTS", "0.0")

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
def mock_hecate(
    sample_hypothesis: HypothesisResult,
    sample_research_result: ResearchResult,
) -> MagicMock:
    mock = MagicMock(spec=HecateClient)
    mock.hypothesis_generator.return_value = sample_hypothesis
    mock.research_new.return_value = sample_research_result
    # No phrase-matched techniques unless a test supplies some.
    mock.candidate_techniques.return_value = []
    # Matches sample_hypothesis's T1003.001 so tests asserting on rendered
    # draft content see real-looking tactics/platform, not an empty lookup.
    mock.lookup_technique.return_value = TechniqueMetadata(
        technique_id="T1003.001",
        tactics=["credential-access"],
        platforms=["Windows"],
        found=True,
    )
    # Default to the failure path so tests that are not about Sigma exercise
    # the graceful degradation. Left as a bare MagicMock this silently
    # rendered a "0 Sigma rule(s)" header into every draft under test, via
    # MagicMock's default __len__/__iter__ -- passing, but testing nothing.
    mock.sigma_generator.return_value = SigmaResult(
        success=False, error="sigma generation not configured in this test"
    )
    # The primary-source step degrades the same way: a failed fetch, so drafts
    # come from the feed text and indicators stay untyped unless a test says
    # otherwise.
    from hecate_agent.core.source_evidence import SourceEvidence

    mock.source_evidence.side_effect = lambda url: SourceEvidence(
        url=url, error="source fetch not configured in this test"
    )
    mock.indicator_records.return_value = []
    return mock


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
