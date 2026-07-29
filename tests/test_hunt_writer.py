"""Tests for hunt_writer rendering and ID allocation."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from sec7669.athf_client import HypothesisResult
from sec7669.hunt_writer import (
    DraftHuntRequest,
    draft_hunt_path,
    hunt_id_lock,
    next_hunt_id,
    render_draft,
    write_draft,
)


def test_next_hunt_id_empty(tmp_path: Path) -> None:
    root = tmp_path / "hunts"
    root.mkdir(parents=True)
    assert next_hunt_id(root) == "H-0001"


def test_next_hunt_id_finds_max(tmp_path: Path) -> None:
    root = tmp_path / "hunts"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / "2026" / "Q3" / "H-0007.md").write_text("stub")
    (root / "2026" / "Q3" / "H-0012.md").write_text("stub")
    (root / "2026" / "Q3" / "H-0011.md").write_text("stub")
    assert next_hunt_id(root) == "H-0013"


def test_next_hunt_id_ignores_non_matches(tmp_path: Path) -> None:
    root = tmp_path / "hunts"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / "2026" / "Q3" / "H-0005.md").write_text("stub")
    (root / "2026" / "Q3" / "notes.md").write_text("stub")
    (root / "2026" / "Q3" / "H-bad.md").write_text("stub")
    assert next_hunt_id(root) == "H-0006"


def test_hunt_id_lock_serializes_concurrent_allocation(tmp_path: Path) -> None:
    """Regression test: without hunt_id_lock, two overlapping writers (a
    manual `sec7669 run` overlapping the hourly timer, or two cycles
    overlapping because one ran long) could both call next_hunt_id() before
    either had written its file, both compute the SAME H-00NN, and the
    second write would silently clobber the first draft's content with no
    error. This drives 5 threads through the exact allocate-then-write
    critical section concurrently, with a deliberate sleep between
    allocation and write to widen the race window, and asserts every writer
    got a unique ID and no file was overwritten."""
    hunts_root = tmp_path / "hunts"
    results: list[tuple[str, str]] = []
    lock = threading.Lock()  # protects the `results` list itself, not the code under test

    def allocate_and_write(marker: str) -> None:
        with hunt_id_lock(hunts_root):
            hunt_id = next_hunt_id(hunts_root)
            path = draft_hunt_path(hunts_root, hunt_id, datetime.now(UTC))
            path.parent.mkdir(parents=True, exist_ok=True)
            time.sleep(0.02)  # widen the allocate-then-write window the race exploited
            path.write_text(marker)
        with lock:
            results.append((hunt_id, marker))

    threads = [threading.Thread(target=allocate_and_write, args=(f"writer-{i}",)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    hunt_ids = [hunt_id for hunt_id, _ in results]
    assert len(hunt_ids) == len(set(hunt_ids)), f"duplicate hunt IDs allocated: {hunt_ids}"
    for hunt_id, marker in results:
        path = draft_hunt_path(hunts_root, hunt_id, datetime.now(UTC))
        assert path.read_text() == marker, f"{hunt_id} was clobbered by another writer"


def test_draft_hunt_path_uses_current_quarter() -> None:
    root = Path("/tmp/hunts")
    when = datetime(2026, 8, 15, tzinfo=UTC)
    assert draft_hunt_path(root, "H-0013", when) == root / "2026" / "Q3" / "H-0013.md"


def test_draft_hunt_path_q1() -> None:
    root = Path("/tmp/hunts")
    when = datetime(2026, 2, 1, tzinfo=UTC)
    assert draft_hunt_path(root, "H-0001", when) == root / "2026" / "Q1" / "H-0001.md"


def test_render_draft_includes_hypothesis(sample_hypothesis: HypothesisResult) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="APT actor X observed dumping LSASS.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "H-0999" in md
    assert "status: planning" in md
    assert "requires-human-review" in md
    assert "T1003.001" in md
    assert sample_hypothesis.hypothesis in md
    assert "APT actor X" in md
    assert "sec7669 DOES NOT auto-generate queries" in md


def test_render_draft_includes_research_link_when_present(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="APT actor X observed dumping LSASS.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
        research_id="R-0004",
    )
    md = render_draft(req)
    assert "spawned_from: R-0004" in md
    assert "R-0004" in md
    assert "research/R-0004.md" in md


def test_render_draft_omits_research_link_when_absent(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="APT actor X observed dumping LSASS.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "spawned_from" not in md
    assert "research grounding unavailable" in md


def test_render_draft_uses_resolved_tactics_and_platforms(
    sample_hypothesis: HypothesisResult,
) -> None:
    """Regression: tactics/platform used to be hardcoded to
    [credential-access]/[Windows] on every draft regardless of what the CTI
    actually described. They must now reflect whatever the orchestrator
    resolved from real ATT&CK technique metadata."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="Adversary manipulates cloud IAM accounts for persistence.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
        tactics=["persistence", "privilege-escalation"],
        platforms=["Linux", "IaaS"],
    )
    md = render_draft(req)
    assert 'tactics: ["persistence", "privilege-escalation"]' in md
    assert 'platform: ["Linux", "IaaS"]' in md
    assert "tactics: [credential-access]" not in md
    assert "platform: [Windows]" not in md


def test_render_draft_falls_back_to_unclassified_when_ttps_unresolved(
    sample_hypothesis: HypothesisResult,
) -> None:
    """When the orchestrator couldn't resolve any tactic/platform (e.g.
    STIX unavailable, unknown technique ID), the draft must say so
    explicitly rather than silently defaulting to a specific, likely-wrong
    tactic/platform."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "tactics: [\"unclassified\"]" in md
    assert "platform: [\"Unknown\"]" in md


def test_render_draft_uses_hypothesis_data_sources(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
    )
    md = render_draft(req)
    assert 'data_sources: ["CrowdStrike", "Sysmon"]' in md


def test_render_draft_handles_empty_hypothesis() -> None:
    req = DraftHuntRequest(
        hunt_id="H-0001",
        threat_intel="nothing here",
        hypothesis=HypothesisResult(),
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "H-0001" in md
    assert "TXXXX" in md  # placeholder technique
    assert "[TBD]" in md


def test_write_draft_creates_file(
    tmp_path: Path,
    sample_hypothesis: HypothesisResult,
) -> None:
    root = tmp_path / "hunts"
    req = DraftHuntRequest(
        hunt_id="H-0042",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    path = write_draft(req, root)
    assert path.exists()
    assert path.name == "H-0042.md"
    assert "H-0042" in path.read_text()
