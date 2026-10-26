"""The hypothesis's platform claim may drop the model's techniques, never the intel's.

H-0014 (Kapibala): the CTI described "PowerShell-based collection and staging",
the candidate merge added T1059.001, the hypothesis said "Linux servers", and
the platform rule dropped T1059.001 as Windows-only -- the hunt shipped with no
techniques at all.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hecate_agent.core.grounding import TechniqueFact

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult, TechniqueMetadata
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

_PLATFORMS = {
    "T1059.001": ["Windows"],  # PowerShell
    "T1207": ["Windows"],  # Rogue Domain Controller
    "T1071.004": ["Linux", "macOS", "Windows"],  # DNS
    "T1546.005": ["Linux", "macOS"],  # Trap
    "T1505.003": ["Windows", "Linux", "macOS", "Network Devices"],  # Web Shell
    "T1059.004": ["Linux", "macOS", "Network Devices"],  # Unix Shell
}


def _lookup(technique_id: str, timeout_sec: int | None = None) -> TechniqueMetadata:
    return TechniqueMetadata(
        technique_id=technique_id,
        tactics=["execution"],
        platforms=_PLATFORMS.get(technique_id, []),
        found=technique_id in _PLATFORMS,
    )


@pytest.fixture
def orch(settings: Settings, mock_hecate: MagicMock) -> Orchestrator:
    mock_hecate.lookup_technique.side_effect = _lookup
    return Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())


def test_an_intel_backed_technique_widens_the_platform_instead_of_vanishing(
    orch: Orchestrator,
) -> None:
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1059.001"], scope_text="Linux servers", facts=facts, protected=["T1059.001"]
    )
    assert platforms == ["Linux", "Windows"]
    assert facts["T1059.001"].valid is True


def test_a_protected_parent_covers_its_sub_technique(orch: Orchestrator) -> None:
    facts: dict[str, TechniqueFact] = {}
    orch._resolve_ttps(["T1059.001"], scope_text="Linux servers", facts=facts, protected=["T1059"])
    assert facts["T1059.001"].valid is True


def test_the_models_own_contradicting_pick_is_still_dropped(orch: Orchestrator) -> None:
    """main's rule stands for what the model chose: T1207 on a macOS hunt."""
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1207"], scope_text="macOS systems", facts=facts, protected=[]
    )
    assert platforms == ["macOS"]
    # Dropped from the hunt, still a real technique: the audit must not call it invented.
    assert "T1207" in orch._platform_dropped
    assert facts["T1207"].valid is True


def test_a_wording_match_does_not_widen_onto_platforms_the_intel_never_names(
    orch: Orchestrator,
) -> None:
    """H-0018: T1546.005 Trap, matched on a research source title, added Linux
    and macOS to a Teams vishing hunt on Windows."""
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1546.005"],
        scope_text="compromised Windows systems",
        facts=facts,
        protected=["T1546.005"],
        asserted=[],
        intel_text="Voice phishing in Microsoft Teams; victims ran a PowerShell one-liner.",
    )
    assert platforms == ["Windows"]
    # Dropped from the hunt, still a real technique: the audit must not call it invented.
    assert "T1546.005" in orch._platform_dropped
    assert facts["T1546.005"].valid is True


def test_a_wording_match_widens_onto_a_platform_the_intel_implies(orch: Orchestrator) -> None:
    """H-0014 still keeps T1059.001: "PowerShell" is itself evidence of Windows."""
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1059.001"],
        scope_text="Linux servers",
        facts=facts,
        protected=["T1059.001"],
        asserted=[],
        intel_text="systematic data exfiltration using PowerShell-based collection and staging",
    )
    assert platforms == ["Linux", "Windows"]
    assert facts["T1059.001"].valid is True


def test_a_technique_the_cti_asserts_widens_whatever_the_text_says(orch: Orchestrator) -> None:
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1546.005"],
        scope_text="compromised Windows systems",
        facts=facts,
        protected=["T1546.005"],
        asserted=["T1546.005"],
        intel_text="no platform words here",
    )
    assert platforms == ["Windows", "Linux", "macOS"]
    assert facts["T1546.005"].valid is True


def test_the_kapibala_draft_keeps_its_technique(
    settings: Settings,
    mock_hecate: MagicMock,
    sample_hypothesis: HypothesisResult,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    mock_hecate.lookup_technique.side_effect = _lookup
    mock_hecate.candidate_techniques.return_value = [("T1059.001", "PowerShell")]
    sample_hypothesis.techniques = []
    sample_hypothesis.hypothesis = "Adversaries exploit WordPress to steal government records"
    sample_hypothesis.location = "Linux servers, WordPress installations, ZyXEL switches"
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="OTX Pulse: Kapibala\nDescription: systematic data exfiltration using "
        "PowerShell-based collection and staging techniques.",
        source="otx",
    )
    result = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    assert result.draft_path is not None
    frontmatter = result.draft_path.read_text().split("---")[1]
    assert 'techniques: ["T1059.001"]' in frontmatter
    assert '"Linux"' in frontmatter and '"Windows"' in frontmatter
    trail = caplog.text
    assert "keeping T1059.001 (the intel names it)" in trail
    assert "not in ATT&CK" not in trail


def test_a_platform_drop_is_not_reported_as_an_unknown_id(
    settings: Settings,
    mock_hecate: MagicMock,
    sample_hypothesis: HypothesisResult,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """H-0014's trail said 'dropped IDs not in ATT&CK: T1059.001'; it was a
    platform drop, already explained at the scope step."""
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    mock_hecate.lookup_technique.side_effect = _lookup
    sample_hypothesis.techniques = ["T1207"]
    sample_hypothesis.hypothesis = "Adversaries deploy backdoors on macOS systems"
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(
        content="MISP Event: X\nSummary: prose", source="misp"
    )
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    assert "T1207 only runs on Windows: dropping it" in caplog.text
    assert "not in ATT&CK" not in caplog.text


def test_scope_without_a_trail_run_still_initialises_drops(
    settings: Settings, mock_hecate: MagicMock, workspace: Path
) -> None:
    orch = Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=MagicMock())
    assert orch._platform_dropped == set()


def test_a_technique_the_cti_asserts_is_never_dropped(orch: Orchestrator) -> None:
    """H-0830: a wrong scope (Identity Provider for a NetScaler report) dropped
    all 17 source-asserted techniques, and the audit then reported T1190 as
    "no such technique in the current ATT&CK matrix"."""
    facts: dict[str, TechniqueFact] = {}
    orch._resolve_ttps(
        ["T1207"],
        scope_text="macOS systems",
        facts=facts,
        protected=["T1207"],
        asserted=["T1207"],
        # Specimen evidence that blocks widening is what left the drop loop
        # free to remove a source-asserted technique.
        specimen=["macOS"],
    )
    assert "T1207" not in orch._platform_dropped
    assert facts["T1207"].valid is True


def test_an_appliance_report_scopes_to_the_appliance(orch: Orchestrator) -> None:
    """H-0830: the specimen evidence named NetScaler throughout and SAML once;
    the hypothesis said Linux. The hunt belongs on Network Devices."""
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1505.003", "T1059.004"],
        scope_text="Linux-based NetScaler appliances",
        facts=facts,
        protected=["T1505.003", "T1059.004"],
        asserted=["T1505.003", "T1059.004"],
        specimen=["Network Devices", "Identity Provider"],
    )
    assert platforms == ["Network Devices"]
    assert not orch._platform_dropped


def test_containers_scope_automatically_inherits_linux(orch: Orchestrator) -> None:
    """Fix 1: Containers platform scope must inherit Linux OS log sources and techniques.
    A hunt scoped to Containers must not drop Linux process/network techniques."""
    facts: dict[str, TechniqueFact] = {}
    _, platforms = orch._resolve_ttps(
        ["T1059.004"],  # Unix Shell (runs on Linux, macOS, Network Devices)
        scope_text="cloud container workloads running Docker and Kubernetes",
        facts=facts,
    )
    # Platforms should include both Containers and Linux via inheritance
    assert "Containers" in platforms
    assert "Linux" in platforms
    assert "T1059.004" not in orch._platform_dropped
