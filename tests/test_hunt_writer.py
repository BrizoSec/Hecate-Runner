"""Tests for hunt_writer rendering and ID allocation."""

from __future__ import annotations

import dataclasses
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from hecate_runner.athf_client import HypothesisResult
from hecate_runner.hunt_writer import (
    DraftHuntRequest,
    _draft_tags,
    _short_title,
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
    manual `hecate-runner run` overlapping the hourly timer, or two cycles
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
    assert "hecate-runner DOES NOT auto-generate queries" in md


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


def test_render_draft_includes_related_hunts_when_present(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="APT actor X observed dumping LSASS.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
        research_id="R-0004",
        related_hunts=["H-0602", "H-0578"],
    )
    md = render_draft(req)
    assert 'related_hunts: ["H-0602", "H-0578"]' in md


def test_render_draft_related_hunts_defaults_to_empty_list(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="APT actor X observed dumping LSASS.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "related_hunts: []" in md


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


def test_short_title_leaves_short_hypothesis_untouched() -> None:
    assert _short_title("Adversaries dump LSASS memory via comsvcs.dll.") == "Adversaries dump LSASS memory via comsvcs.dll."


def test_short_title_truncates_on_word_boundary_with_ellipsis() -> None:
    # Regression test: the old `hyp.hypothesis[:80]` hard-cut sliced
    # mid-word with no ellipsis, so a reader saw what looked like a
    # complete (but nonsensical) title -- e.g. "...on high-valu" -- with no
    # indication anything had been cut off.
    hypothesis = (
        "Adversaries use JADEPUFFER ransomware to disrupt AI infrastructures "
        "on high-value cloud tenants via supply chain compromise"
    )
    title = _short_title(hypothesis)
    assert len(title) <= 104  # 100-char cap + "..."
    assert title.endswith("...")
    assert not title[:-3].endswith(" ")
    # No word straddles the cut: every prefix word of the truncated title
    # must actually appear as a whole word in the source hypothesis.
    for word in title[:-3].split():
        assert word in hypothesis.split()


def test_short_title_defaults_when_hypothesis_empty() -> None:
    assert _short_title("") == "Untitled draft"


def test_render_draft_includes_source_url_when_present(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
        source_url="https://thedfirreport.com/2026/06/29/example",
    )
    md = render_draft(req)
    assert "https://thedfirreport.com/2026/06/29/example" in md
    assert "CTI Sources & References:** [Review CTI and populate]" not in md


def test_render_draft_falls_back_to_placeholder_without_source_url(
    sample_hypothesis: HypothesisResult,
) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "CTI Sources & References:** [Review CTI and populate]" in md


def test_render_draft_uses_able_scoping_when_present(
    sample_hypothesis: HypothesisResult,
) -> None:
    hyp = dataclasses.replace(
        sample_hypothesis,
        actor="Generic post-exploitation toolkit",
        behavior="Direct syscalls to bypass userland EDR hooks",
        location="Windows domain-joined endpoints",
        evidence="EDR process telemetry - process.name, access.mask",
    )
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
        source_url="https://example.com/report",  # isolates this test to ABLE, not CTI Sources
    )
    md = render_draft(req)
    assert "Generic post-exploitation toolkit" in md
    assert "Direct syscalls to bypass userland EDR hooks" in md
    assert "Windows domain-joined endpoints" in md
    assert "EDR process telemetry - process.name, access.mask" in md
    assert "[Review CTI and populate]" not in md


def test_render_draft_falls_back_to_placeholder_for_empty_able_fields(
    sample_hypothesis: HypothesisResult,
) -> None:
    """sample_hypothesis leaves actor/behavior/location/evidence at their
    default empty string -- each must fall back to the honest placeholder,
    not render as a blank table cell. That's 4 ABLE fields plus "CTI
    Sources & References" (also unset here, no source_url) -- 5 total."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert md.count("[Review CTI and populate]") == 5


def test_render_draft_escapes_pipe_in_able_field() -> None:
    """A `|` in an ABLE field would otherwise break the markdown table's
    column layout."""
    hyp = HypothesisResult(
        hypothesis="test",
        actor="APT1 | APT2 (uncertain attribution)",
    )
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "APT1 \\| APT2 (uncertain attribution)" in md


def test_draft_tags_appends_low_confidence_tag_when_not_threat_report() -> None:
    assert _draft_tags(is_threat_report=False) == [
        "draft",
        "auto-generated",
        "requires-human-review",
        "low-confidence-source",
    ]


def test_draft_tags_omits_low_confidence_tag_when_threat_report() -> None:
    assert _draft_tags(is_threat_report=True) == ["draft", "auto-generated", "requires-human-review"]


def test_render_draft_shows_low_confidence_banner_and_tag(
    sample_hypothesis: HypothesisResult,
) -> None:
    """Regression test: found via a live end-to-end run where a CrowdStrike
    compliance/marketing blog post (no adversary behavior described) still
    produced a confident-sounding hypothesis and "Adversary Tradecraft"-
    shaped narrative with nothing flagging it as speculative."""
    hyp = dataclasses.replace(
        sample_hypothesis,
        is_threat_report=False,
        low_confidence_reason="Source is a vendor compliance announcement; no adversary behavior is described.",
    )
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "LOW-CONFIDENCE SOURCE" in md
    assert "Source is a vendor compliance announcement; no adversary behavior is described." in md
    assert '"low-confidence-source"' in md


def test_render_draft_omits_low_confidence_banner_when_threat_report(
    sample_hypothesis: HypothesisResult,
) -> None:
    """sample_hypothesis defaults is_threat_report to True -- no banner, no tag."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "LOW-CONFIDENCE SOURCE" not in md
    assert "low-confidence-source" not in md


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
