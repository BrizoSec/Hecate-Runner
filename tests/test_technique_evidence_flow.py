"""Evidence-gated technique mapping through a cycle (deep-dive item #4)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.hecate_client import HypothesisResult, TechniqueMetadata
from hecate_runner.orchestrator import Orchestrator

CTI = (
    "OTX Pulse: A fake resume installed VShell\n"
    "Description: A Chinese-language executable disguised as a resume delivers VShell. "
    "The loader uses sandbox detection, CPU checks, and sleep-timer evasion. "
    "The RAT provides operators with command execution, file access and screen capture capabilities."
)

NAMES = {
    "T1113": "Screen Capture",
    "T1036": "Masquerading",
    "T1036.001": "Invalid Code Signature",
    "T1204.002": "Malicious File",
    "T1497.001": "System Checks",
    "T1497.003": "Time Based Checks",
    "T1041": "Exfiltration Over C2 Channel",
}


def _lookup(technique_id: str, timeout_sec: int | None = None) -> TechniqueMetadata:
    name = NAMES.get(technique_id.upper())
    return TechniqueMetadata(
        technique_id=technique_id.upper(),
        name=name or "",
        tactics=["stealth"],
        platforms=["Windows"],
        found=bool(name),
    )


def _draft(
    settings: Settings, hecate: MagicMock, content: str = CTI, model_picks: list[str] | None = None
) -> str:
    hypothesis = HypothesisResult(
        hypothesis="Adversaries deliver VShell through a fake resume",
        techniques=list(model_picks or []),
        data_sources=["process_execution"],
        observables=["resume.exe"],
    )
    hecate.hypothesis_generator.return_value = hypothesis
    hecate.lookup_technique.side_effect = _lookup
    provider = MagicMock()
    provider.next_item.return_value = CTIItem(content=content, source="otx", title="VShell")
    return (
        Orchestrator(settings=settings, hecate=hecate, cti_provider=provider)
        .run_once()
        .draft_path.read_text()
    )


def _techniques(draft: str) -> str:
    return next(
        line for line in draft.split("---", 2)[1].splitlines() if line.startswith("techniques:")
    )


@pytest.fixture
def hecate(mock_hecate: MagicMock) -> MagicMock:
    # The name matcher proposes Screen Capture from the capability sentence, as it did on H-0618.
    mock_hecate.candidate_techniques.return_value = [("T1113", "Screen Capture")]
    return mock_hecate


def test_described_behaviour_is_mapped_with_its_passage(
    settings: Settings, hecate: MagicMock
) -> None:
    draft = _draft(settings, hecate)
    techniques = _techniques(draft)
    for technique in ("T1204.002", "T1036", "T1497.001", "T1497.003"):
        assert technique in techniques
    table = draft.split("#### Technique Evidence", 1)[1]
    assert (
        '| T1497.001 | observed | "The loader uses sandbox detection, CPU checks, and sleep-timer evasion."'
        in table
    )


def test_a_capability_only_technique_is_dropped_and_listed(
    settings: Settings, hecate: MagicMock
) -> None:
    draft = _draft(settings, hecate)
    assert "T1113" not in _techniques(draft)
    tail = draft.split("Not mapped, capability only", 1)[1]
    assert (
        '- T1113: "The RAT provides operators with command execution, file access and screen capture capabilities."'
        in tail
    )


def test_an_unsupported_sub_technique_is_generalised_to_its_supported_parent(
    settings: Settings, hecate: MagicMock
) -> None:
    techniques = _techniques(_draft(settings, hecate, model_picks=["T1036.001"]))
    assert "T1036.001" not in techniques and "T1036" in techniques


def test_a_technique_the_cti_names_by_id_is_kept(settings: Settings, hecate: MagicMock) -> None:
    content = CTI + "\nMITRE ATT&CK Techniques: T1041"
    hecate.candidate_techniques.return_value = []
    item = CTIItem(
        content=content, source="misp", title="VShell", metadata={"techniques": ["T1041"]}
    )
    hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="x", techniques=[], observables=["a.exe"]
    )
    hecate.lookup_technique.side_effect = _lookup
    provider = MagicMock()
    provider.next_item.return_value = item
    draft = (
        Orchestrator(settings=settings, hecate=hecate, cti_provider=provider)
        .run_once()
        .draft_path.read_text()
    )
    assert "T1041" in _techniques(draft)


def test_cti_asserted_capability_technique_is_dropped_as_capability_only(
    settings: Settings, hecate: MagicMock
) -> None:
    content = CTI + "\nMITRE ATT&CK Techniques: T1113"
    hecate.candidate_techniques.return_value = []
    item = CTIItem(
        content=content, source="misp", title="VShell", metadata={"techniques": ["T1113"]}
    )
    hecate.hypothesis_generator.return_value = HypothesisResult(
        hypothesis="x", techniques=[], observables=["a.exe"]
    )
    hecate.lookup_technique.side_effect = _lookup
    provider = MagicMock()
    provider.next_item.return_value = item
    draft = (
        Orchestrator(settings=settings, hecate=hecate, cti_provider=provider)
        .run_once()
        .draft_path.read_text()
    )
    assert "T1113" not in _techniques(draft)
