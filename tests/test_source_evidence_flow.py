"""Primary-source evidence through a cycle: research, hypothesis, Sigma, draft, trail."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest
from hecate_agent.core.provenance import IndicatorRecord
from hecate_agent.core.source_evidence import SourceArtifact, SourceEvidence

from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME

REPORT = "https://report.example/vshell"
LOADER = "81c51138d5527ca7dcc258171eb36659c479f66c86a8947b6340d040b3860a30"
DECODED = "c666ac4f1a1b8df7ccfe8b19705279acd8b7eb7a4d0b3802bb3465064883ab25"

ITEM = CTIItem(
    content=(
        "OTX Pulse: A fake resume installed VShell\n"
        "Description: A resume executable launches cmd.exe and a fileless VShell RAT.\n"
        f"Indicators (2 total): FileHash-SHA256 (2)\nReferences: {REPORT}"
    ),
    source="otx",
    title="A fake resume installed VShell",
    metadata={"indicators": {"FileHash-SHA256": [LOADER, DECODED]}},
)

EVIDENCE = SourceEvidence(
    url=REPORT,
    chars=32920,
    chunks=4,
    text=f"The resume executable launches cmd.exe. Go loader SHA-256 {LOADER}. Decoded SHA-256: {DECODED}",
    artifacts=[
        SourceArtifact(
            "cmd.exe",
            "process",
            "spawned shell",
            "active",
            "unknown",
            "The resume executable launches cmd.exe.",
        ),
        SourceArtifact(
            LOADER, "sha256", "executable", "active", "unknown", f"Go loader SHA-256 {LOADER}"
        ),
    ],
    indicators=[
        IndicatorRecord(
            LOADER, "sha256", "executable", "active", source=REPORT, evidence="Go loader"
        )
    ],
)

RECORDS = [
    IndicatorRecord(LOADER, "sha256", "executable", "active", source=REPORT, evidence="Go loader"),
    IndicatorRecord(DECODED, "sha256", "memory_only", "active", source=REPORT, evidence="Decoded"),
]


def _run(settings: Settings, mock_hecate: MagicMock, item: CTIItem = ITEM):
    provider = MagicMock()
    provider.next_item.return_value = item
    return Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()


@pytest.fixture
def evidence_hecate(mock_hecate: MagicMock) -> MagicMock:
    mock_hecate.source_evidence.side_effect = None
    mock_hecate.source_evidence.return_value = EVIDENCE
    mock_hecate.indicator_records.return_value = RECORDS
    return mock_hecate


def test_evidence_reaches_research_and_the_hypothesis(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    _run(settings, evidence_hecate)
    evidence_hecate.source_evidence.assert_called_once_with(REPORT)
    context = evidence_hecate.research_new.call_args.kwargs["source_context"]
    assert (
        context.startswith(ITEM.content)
        and "Primary source (" in context
        and "[process] cmd.exe" in context
    )
    assert (
        "Primary source (" in evidence_hecate.hypothesis_generator.call_args.kwargs["threat_intel"]
    )


def test_sigma_gets_typed_records_and_only_routable_indicators(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    _run(settings, evidence_hecate)
    payload = evidence_hecate.sigma_generator.call_args.args[0]
    assert [r["role"] for r in payload["indicator_records"]] == ["executable", "memory_only"]
    assert payload["indicators"] == {
        "sha256": [LOADER]
    }  # the in-memory payload is not offered to the model
    assert "cmd.exe" in payload["observables"]


def test_the_draft_carries_the_evidence_and_each_indicators_role(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    draft = _run(settings, evidence_hecate).draft_path.read_text()
    section = draft.split("### Primary Source Evidence", 1)[1].split("### Justification", 1)[0]
    assert f"[{REPORT}]({REPORT})" in section and "32,920 characters" in section
    assert "`cmd.exe` | process" in section
    assert "| memory_only | active |" in section and "none: exists only in memory" in section
    assert "| executable | active |" in section and "process_creation" in section


def test_the_trail_reports_what_the_source_step_found(
    settings: Settings, evidence_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    _run(settings, evidence_hecate)
    line = next(
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER_NAME and " source " in r.getMessage()
    )
    assert "2 artifact(s) verified" in line and "2/2 indicator(s) typed" in line


def test_a_failed_fetch_drafts_from_the_feed_as_before(
    settings: Settings, mock_hecate: MagicMock
) -> None:
    result = _run(settings, mock_hecate)
    assert result.outcome == "draft_created"
    assert mock_hecate.research_new.call_args.kwargs["source_context"] == ITEM.content
    assert mock_hecate.sigma_generator.call_args.args[0]["indicator_records"] == []
    mock_hecate.indicator_records.assert_not_called()


def test_the_step_can_be_turned_off(settings: Settings, evidence_hecate: MagicMock) -> None:
    settings.source_evidence_enabled = False
    _run(settings, evidence_hecate)
    evidence_hecate.source_evidence.assert_not_called()


def test_an_item_without_a_report_link_skips_the_fetch(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    item = CTIItem(content="OTX Pulse: X\nDescription: prose about an intrusion.", source="otx")
    _run(settings, evidence_hecate, item)
    evidence_hecate.source_evidence.assert_not_called()


def test_sigma_gets_the_verified_artifacts_for_two_pass_generation(
    settings: Settings, evidence_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    """A1: pass one's exact values come from the verified artifacts, and the trail lists them."""
    caplog.set_level(logging.INFO)
    _run(settings, evidence_hecate)
    payload = evidence_hecate.sigma_generator.call_args.args[0]
    assert [a["value"] for a in payload["source_artifacts"]] == ["cmd.exe", LOADER]
    trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
    assert any(
        "pass 1: 1 exact value(s) from the source rules may match: \\cmd.exe" in m for m in trail
    )


def test_observables_the_pipeline_knows_are_unobservable_are_removed(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    """A3 replay: a memory-only hash was listed as something suspicious to look for."""
    evidence_hecate.hypothesis_generator.return_value.observables = ["cmd.exe", DECODED]
    draft = _run(settings, evidence_hecate).draft_path.read_text()
    suspicious = draft.split("### What Suspicious Looks Like", 1)[1].split("###", 1)[0]
    assert "cmd.exe" in suspicious and DECODED not in suspicious
    assert f'- removed (observables): "{DECODED}" - exists only in memory' in draft


def test_sigma_gets_the_commands_the_source_shows_being_run(
    settings: Settings, evidence_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    evidence_hecate.source_evidence.return_value = SourceEvidence(
        url=REPORT,
        chars=100,
        chunks=1,
        # Two macOS markers (Mach-O, osascript) scope the hunt to macOS, where xattr runs.
        text="The Mach-O loader then ran xattr -d com.apple.quarantine $HOME/Library/x/y. "
        "An osascript dialog prompted the victim for a password.",
    )
    _run(settings, evidence_hecate)
    payload = evidence_hecate.sigma_generator.call_args.args[0]
    assert [c["title"] for c in payload["observed_commands"]] == ["xattr -d com.apple.quarantine"]
    trail = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME]
    assert any(
        "1 command(s) the source shows being run: xattr -d com.apple.quarantine" in m for m in trail
    )


TOKEN = "f90c8b1dcd374d4f552744ee1765583d"


def test_a_token_a_target_and_an_attacker_side_file_are_explained_and_kept_out_of_sigma(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    """The Redis botnet replay: a C2 bearer token listed as an MD5, a QA target typed as C2, the operator's own file."""
    evidence_hecate.indicator_records.return_value = [
        *RECORDS,
        IndicatorRecord(
            TOKEN, "md5", "non_file", "active", source=REPORT, evidence=f"C2_TOKEN={TOKEN}"
        ),
        IndicatorRecord(
            "47.250.92.230", "ipv4", "target", "active", source=REPORT, evidence="QA target"
        ),
    ]
    evidence_hecate.source_evidence.return_value = SourceEvidence(
        url=REPORT,
        chars=EVIDENCE.chars,
        chunks=EVIDENCE.chunks,
        text=EVIDENCE.text,
        artifacts=[
            *EVIDENCE.artifacts,
            SourceArtifact(
                "redis_fleet.txt",
                "file_path",
                "attacker-side",
                "unknown",
                "unknown",
                "The operator works from redis_fleet.txt, sitting in the directory.",
            ),
        ],
        indicators=EVIDENCE.indicators,
    )
    draft = _run(settings, evidence_hecate).draft_path.read_text()
    section = draft.split("### Primary Source Evidence", 1)[1].split("### Justification", 1)[0]
    assert "none: a token, key or certificate fingerprint, not the hash of a file" in section
    assert "none: an address the actor targeted, not infrastructure a host connects to" in section
    payload = evidence_hecate.sigma_generator.call_args.args[0]
    assert payload["indicators"] == {"sha256": [LOADER]}
    assert "redis_fleet.txt" not in payload["observables"] and "cmd.exe" in payload["observables"]


def test_values_the_model_names_from_the_actors_side_or_another_platform_are_removed(
    settings: Settings, evidence_hecate: MagicMock
) -> None:
    """The Redis botnet draft listed the operator's C2 script and python.exe on a Linux hunt."""
    report = (
        "An exposed directory held the operator's entire working toolkit, and everything here "
        "traces back to the operator's own files. A batch script launches c2_persist.py, the C2 "
        "server. On each victim the cron job writes /tmp/.cache and runs it."
    )
    evidence_hecate.source_evidence.return_value = SourceEvidence(
        url=REPORT, chars=len(report), chunks=1, text=report, artifacts=EVIDENCE.artifacts
    )
    evidence_hecate.lookup_technique.return_value.platforms = ["Linux"]
    hypothesis = evidence_hecate.hypothesis_generator.return_value
    hypothesis.observables = ["c2_persist.py", "python.exe", "/tmp/.cache"]
    hypothesis.location = "Linux servers"
    draft = _run(settings, evidence_hecate).draft_path.read_text()
    assert (
        '- removed (observables): "c2_persist.py" - the source places it on the actor\'s own side'
        in draft
    )
    assert (
        '- removed (observables): "python.exe" - is a Windows artifact; this hunt covers' in draft
    )
    suspicious = draft.split("### What Suspicious Looks Like", 1)[1].split("###", 1)[0]
    assert "/tmp/.cache" in suspicious and "python.exe" not in suspicious
