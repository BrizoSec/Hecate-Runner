from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from hecate_runner.config import Settings
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, render_draft
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.purple_team import BENIGN_SAMPLE, replay_events, replay_rule

_POWERSHELL_SIGMA_RULE = """title: Suspicious PowerShell Download Cradle
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \\powershell.exe
    CommandLine|contains:
      - Invoke-WebRequest
      - DownloadString
  condition: selection
"""

_WINDOWS_SERVICE_RULE = """title: Windows Service Creation via SC.EXE
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \\sc.exe
    CommandLine|contains:
      - create
  condition: selection
"""

_OVERLY_BROAD_RULE = """title: Any PowerShell Execution
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - \\powershell.exe
  condition: selection
"""


def test_replay_events_with_atomic_emulation_powershell() -> None:
    # Empty static records and artifacts; technique alone drives dynamic emulation
    events = replay_events([], [], cti_text="", techniques=["T1059.001"], enable_atomic=True)
    assert "process_creation" in events
    assert any(
        "powershell.exe" in str(e.get("Image", "")).lower() for e in events["process_creation"]
    )
    assert any(
        "Invoke-WebRequest" in str(e.get("CommandLine", "")) for e in events["process_creation"]
    )
    assert "file_event" in events
    assert any("p.ps1" in str(e.get("TargetFilename", "")) for e in events["file_event"])


def test_replay_events_with_atomic_emulation_windows_service() -> None:
    events = replay_events([], [], cti_text="", techniques=["T1543.003"], enable_atomic=True)
    assert "process_creation" in events
    assert any("sc.exe" in str(e.get("Image", "")).lower() for e in events["process_creation"])
    assert "registry_set" in events
    assert any("Services" in str(e.get("TargetObject", "")) for e in events["registry_set"])


def test_sigma_rule_validates_against_atomic_adversary_emulation() -> None:
    events = replay_events([], [], cti_text="", techniques=["T1059.001"], enable_atomic=True)
    outcome = replay_rule(
        _POWERSHELL_SIGMA_RULE,
        events["process_creation"],
        BENIGN_SAMPLE,
        emulated_techniques=["T1059.001"],
    )
    assert outcome.status == "validated"
    assert outcome.validated is True
    assert outcome.true_positives >= 1
    assert outcome.false_positives == 0
    assert outcome.emulation_type == "atomic_red_team"
    assert "T1059.001" in outcome.emulated_techniques


def test_atomic_emulation_flags_false_positive_on_benign_sample() -> None:
    events = replay_events([], [], cti_text="", techniques=["T1059.001"], enable_atomic=True)
    # _OVERLY_BROAD_RULE matches both the atomic test AND the benign monitoring script in BENIGN_SAMPLE
    outcome = replay_rule(_OVERLY_BROAD_RULE, events["process_creation"], BENIGN_SAMPLE)
    assert outcome.status == "baseline_match"
    assert outcome.validated is False
    assert outcome.false_positives >= 1


def test_orchestrator_purple_team_atomic_flow(tmp_path: Path) -> None:
    out_dir = tmp_path / "queries" / "H-1234"
    out_dir.mkdir(parents=True)
    rule_file = out_dir / "ps_cradle.yml"
    rule_file.write_text(_POWERSHELL_SIGMA_RULE, encoding="utf-8")

    rules = [
        {
            "logsource_category": "process_creation",
            "rule_yaml": _POWERSHELL_SIGMA_RULE,
            "path": str(rule_file),
            "techniques": ["T1059.001"],
        }
    ]

    req = DraftHuntRequest(
        hunt_id="H-1234",
        threat_intel="Adversary leveraged PowerShell download cradle to pull second-stage payloads.",
        hypothesis=MagicMock(),
        generated_at=datetime.now(UTC),
    )

    orch = Orchestrator(
        settings=Settings(hecate_workspace=tmp_path, purple_team_atomic_emulation=True),
        hecate=MagicMock(),
        cti_provider=MagicMock(),
    )
    orch.trail = MagicMock()
    orch.trail.elapsed = 1.0
    orch._indicator_records = []
    orch._source_evidence = SimpleNamespace(artifacts=[], text="")
    orch._technique_evidence = [{"technique_id": "T1059.001"}]

    item = MagicMock()
    item.metadata = {"techniques": ["T1059.001"]}
    item.content = "Adversary used PowerShell to download files."

    orch._run_purple_team_validation(req, rules, out_dir, item)

    assert req.purple_team_rules_evaluated == 1
    assert req.purple_team_rules_validated == 1
    assert "T1059.001" in req.purple_team_atomic_techniques
    assert len(req.purple_team_atomic_tests) > 0
    assert "x_hecate_purple_team_validated: true" in rule_file.read_text(encoding="utf-8")


def test_hunt_writer_renders_atomic_emulation_details(sample_hypothesis: HypothesisResult) -> None:
    sample_hypothesis.techniques = ["T1059.001"]
    req = DraftHuntRequest(
        hunt_id="H-5678",
        threat_intel="Test",
        hypothesis=sample_hypothesis,
        generated_at=datetime.now(UTC),
        sigma_rules=[
            {
                "logsource_category": "process_creation",
                "title": "Suspicious PowerShell Cradle",
                "level": "high",
                "techniques": ["T1059.001"],
                "rule_yaml": _POWERSHELL_SIGMA_RULE,
                "purple_team": {"status": "validated", "validated": True},
            }
        ],
        purple_team_rules_evaluated=1,
        purple_team_rules_validated=1,
        purple_team_atomic_techniques=["T1059.001"],
        purple_team_atomic_tests=[
            {
                "technique_id": "T1059.001",
                "test_id": "ART T1059.001 #1",
                "name": "PowerShell Download and Execute",
                "command": "powershell.exe -NoP -NonI -Command ...",
            }
        ],
    )
    md = render_draft(req)
    assert "purple_team_validated: true" in md
    assert "Adversary Emulation (Atomic Red Team):" in md
    assert "`T1059.001`" in md
