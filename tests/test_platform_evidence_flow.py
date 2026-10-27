"""Evidence-based platform scoping through a cycle (deep-dive item #6)."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest
from hecate_agent.core.source_evidence import SourceEvidence

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult, TechniqueMetadata
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

REPORT = "https://report.example/vshell"
ITEM = CTIItem(
    content=f"OTX Pulse: A fake resume installed VShell\nDescription: A resume executable.\nReferences: {REPORT}",
    source="otx",
    title="A fake resume installed VShell",
)
PAGE = (
    "ANY.RUN showed the executable launching cmd.exe, opening a DOCX in Word. "
    "The stager resolves kernel32 exports and loads activeds.dll.\n"
    "UNC5174's published chains were mainly Linux, using ELF droppers."
)
#: Where each technique runs, per ATT&CK: T1059.004 Unix Shell is Linux/macOS only.
PLATFORMS = {
    "T1059.003": ["Windows"],
    "T1204.002": ["Windows", "Linux", "macOS"],
    "T1059.004": ["Linux", "macOS"],
}


def _lookup(technique_id: str, timeout_sec: int | None = None) -> TechniqueMetadata:
    return TechniqueMetadata(
        technique_id=technique_id,
        name=technique_id,
        tactics=["execution"],
        platforms=PLATFORMS.get(technique_id, ["Windows"]),
        found=True,
    )


@pytest.fixture
def run(settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO)
    mock_hecate.source_evidence.side_effect = None
    mock_hecate.source_evidence.return_value = SourceEvidence(
        url=REPORT, chars=len(PAGE), chunks=1, text=PAGE
    )
    mock_hecate.lookup_technique.side_effect = _lookup
    mock_hecate.candidate_techniques.return_value = [("T1059.003", "Windows Command Shell")]
    mock_hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="Adversaries deliver VShell through a fake resume on Linux and Windows workstations",
        location="Linux and Windows workstations at research institutes",
        techniques=["T1059.003", "T1204.002"],
        observables=["cmd.exe spawned by a resume-named executable"],
    )
    provider = MagicMock()
    provider.next_item.return_value = ITEM

    def _run() -> tuple[str, list[str]]:
        result = Orchestrator(
            settings=settings, hecate=mock_hecate, cti_provider=provider
        ).run_once()
        trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
        return result.draft_path.read_text(), trail

    return _run


def _frontmatter_line(draft: str, key: str) -> str:
    return next(
        line for line in draft.split("---", 2)[1].splitlines() if line.startswith(f"{key}:")
    )


def test_the_specimens_evidence_outranks_the_models_location(run) -> None:
    draft, trail = run()
    assert _frontmatter_line(draft, "platform") == 'platform: ["Windows"]'
    shown = next(m for m in trail if "the specimen's evidence shows Windows:" in m)
    assert all(marker in shown for marker in ("cmd.exe", "kernel32", "activeds.dll"))
    assert any(
        "the specimen's evidence shows only Windows: not scoping to Linux" in m for m in trail
    )


def test_the_models_platform_claim_is_flagged_in_the_claim_audit(run) -> None:
    draft, _ = run()
    audit = draft.split("#### Claim Audit", 1)[1]
    assert '- flagged (location): "Linux and Windows workstations at research institutes"' in audit
    assert "names Linux, but the specimen's evidence shows only Windows" in audit


def test_a_technique_cannot_widen_onto_a_platform_the_evidence_does_not_show(
    run, mock_hecate: MagicMock
) -> None:
    mock_hecate.candidate_techniques.return_value = [
        ("T1059.003", "Windows Command Shell"),
        ("T1059.004", "Unix Shell"),
    ]
    draft, trail = run()
    assert _frontmatter_line(draft, "platform") == 'platform: ["Windows"]'
    assert "T1059.004" not in _frontmatter_line(draft, "techniques")
    assert any("dropped unevidenced feed tags: T1059.004" in m for m in trail)


def test_hybrid_cloud_container_platforms_recognized(
    settings: Settings, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    cloud_page = (
        "UNC-3882 compromised Entra ID, performed sts:AssumeRole in AWS, "
        "used nsenter for container breakout on Kubernetes worker nodes, "
        "and spawned bash on Linux."
    )
    mock_hecate.source_evidence.side_effect = None
    mock_hecate.source_evidence.return_value = SourceEvidence(
        url="https://report.example/cloud-hybrid",
        chars=len(cloud_page),
        chunks=1,
        text=cloud_page,
    )
    platforms_map = {
        "T1611": ["Containers"],
        "T1059.004": ["Linux"],
        "T1550.001": ["Identity Provider", "IaaS"],
    }
    mock_hecate.lookup_technique.side_effect = lambda tid, timeout_sec=None: TechniqueMetadata(
        technique_id=tid,
        name=tid,
        tactics=["execution"],
        platforms=platforms_map.get(tid, ["Linux"]),
        found=True,
    )
    mock_hecate.candidate_techniques.return_value = [
        ("T1611", "Escape to Host"),
        ("T1059.004", "Unix Shell"),
        ("T1550.001", "Application Access Token"),
    ]
    mock_hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis=(
            "Adversaries abuse OAuth tokens in Entra ID, execute container breakout "
            "in Kubernetes, and run commands on Linux"
        ),
        location="Kubernetes containers, Entra ID, and Linux hosts",
        techniques=["T1611", "T1059.004", "T1550.001"],
        observables=["nsenter container escape"],
    )
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content=(
            "OTX Pulse: Hybrid Intrusion\n"
            "Description: Cloud to host.\n"
            "References: https://report.example/cloud-hybrid"
        ),
        source="otx",
        title="Hybrid Intrusion",
    )
    result = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()
    draft = result.draft_path.read_text()
    pf_line = _frontmatter_line(draft, "platform")
    for expected in ("Containers", "Identity Provider", "Linux"):
        assert expected in pf_line
