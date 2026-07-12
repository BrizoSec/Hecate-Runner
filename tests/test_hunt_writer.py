"""Tests for hunt_writer rendering and ID allocation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sec7669.athf_client import HypothesisResult
from sec7669.hunt_writer import (
    DraftHuntRequest,
    draft_hunt_path,
    next_hunt_id,
    render_draft,
    write_draft,
)


def test_next_hunt_id_empty(tmp_path: Path) -> None:
    root = tmp_path / "hunts" / "production"
    root.mkdir(parents=True)
    assert next_hunt_id(root) == "H-0001"


def test_next_hunt_id_finds_max(tmp_path: Path) -> None:
    root = tmp_path / "hunts" / "production"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / "2026" / "Q3" / "H-0007.md").write_text("stub")
    (root / "2026" / "Q3" / "H-0012.md").write_text("stub")
    (root / "2026" / "Q3" / "H-0011.md").write_text("stub")
    assert next_hunt_id(root) == "H-0013"


def test_next_hunt_id_ignores_non_matches(tmp_path: Path) -> None:
    root = tmp_path / "hunts" / "production"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / "2026" / "Q3" / "H-0005.md").write_text("stub")
    (root / "2026" / "Q3" / "notes.md").write_text("stub")
    (root / "2026" / "Q3" / "H-bad.md").write_text("stub")
    assert next_hunt_id(root) == "H-0006"


def test_draft_hunt_path_uses_current_quarter() -> None:
    root = Path("/tmp/hunts/production")
    when = datetime(2026, 8, 15, tzinfo=UTC)
    assert draft_hunt_path(root, "H-0013", when) == root / "2026" / "Q3" / "H-0013.md"


def test_draft_hunt_path_q1() -> None:
    root = Path("/tmp/hunts/production")
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
    root = tmp_path / "hunts" / "production"
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
