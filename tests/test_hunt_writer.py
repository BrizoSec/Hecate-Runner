"""Tests for hunt_writer rendering and ID allocation."""

from __future__ import annotations

import dataclasses
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from hecate_agent.core.hunt_ids import hunt_id_lock, next_hunt_id

from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import (
    DraftHuntRequest,
    _draft_tags,
    _short_title,
    _title_scalar,
    draft_hunt_path,
    embedded_cti,
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


def test_next_hunt_id_skips_ids_with_orphaned_query_artifacts(tmp_path: Path) -> None:
    """A deleted hunt leaves its Sigma rules behind under queries/, keyed by
    hunt ID. Without this floor the reallocated ID silently adopts them: after
    a counter reset the new H-0001 inherited the deleted H-0001's rule about
    Redis exploitation, and the draft pointed a reviewer at a directory holding
    two unrelated detections."""
    root = tmp_path / "hunts"
    root.mkdir(parents=True)
    queries = tmp_path / "queries"
    (queries / "H-0009").mkdir(parents=True)
    (queries / "H-0009" / "file_event__old_rule.yml").write_text("title: old")

    assert next_hunt_id(root) == "H-0010"


def test_next_hunt_id_takes_the_highest_floor(tmp_path: Path) -> None:
    """Hunt documents and query artifacts are independent floors."""
    root = tmp_path / "hunts"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / "2026" / "Q3" / "H-0020.md").write_text("stub")
    queries = tmp_path / "queries"
    (queries / "H-0005").mkdir(parents=True)

    assert next_hunt_id(root) == "H-0021"


def test_next_hunt_id_ignores_non_hunt_entries_under_queries(tmp_path: Path) -> None:
    root = tmp_path / "hunts"
    root.mkdir(parents=True)
    queries = tmp_path / "queries"
    queries.mkdir()
    (queries / "H-0003").mkdir()
    (queries / "scratch").mkdir()
    (queries / "H-bad").mkdir()
    (queries / "H-0099.yml").write_text("a file, not a hunt directory")

    assert next_hunt_id(root) == "H-0004"


def test_next_hunt_id_unaffected_when_queries_dir_is_absent(tmp_path: Path) -> None:
    root = tmp_path / "hunts"
    root.mkdir(parents=True)
    assert next_hunt_id(root) == "H-0001"


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
    # No rules supplied -> the section degrades to a human-to-draft
    # placeholder rather than looking like queries exist.
    assert "[Human to draft based on Observe section" in md


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


def test_render_draft_includes_claim_evidence_checks(sample_hypothesis: HypothesisResult) -> None:
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="APT actor X observed dumping LSASS.",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
        claim_evidence=[
            {
                "field": "hypothesis",
                "claim": "dumping LSASS",
                "quote": "APT actor X observed dumping LSASS.",
                "source": "https://example.com/report",
                "status": "quote found; relevance needs review",
            }
        ],
    )

    md = render_draft(req)

    assert "#### Claim Evidence References" in md
    assert "quote found; relevance needs review" in md
    assert "[https://example.com/report](https://example.com/report)" in md


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
    assert "Research Context:** None — review the CTI directly" in md


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


def test_render_draft_leaves_unresolved_ttps_empty_in_frontmatter(
    sample_hypothesis: HypothesisResult,
) -> None:
    """When the orchestrator couldn't resolve any tactic/platform (e.g.
    STIX unavailable, unknown technique ID), the frontmatter must be empty
    rather than carrying a stand-in.

    Regression test: the stand-ins used to be "unclassified"/"Unknown",
    which `hecate-agent hunt validate` checks against the ATT&CK matrix and
    rejects -- so drafts were written already failing the framework's own
    validator. The gap is still stated for the reviewer, in the body."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="test intel",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 7, 4, 22, 0, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "tactics: []" in md
    assert "platform: []" in md
    assert "unclassified" not in md


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
    assert "[TBD]" in md
    # An unmapped technique list reads as a gap in the body and is simply
    # absent from frontmatter -- never a "TXXXX" stand-in, which both fails
    # `hecate-agent hunt validate` and reads as a real ATT&CK ID at a glance.
    assert "TXXXX" not in md
    assert "techniques: []" in md
    assert "**MITRE ATT&CK:** [none mapped - human to populate]" in md


def test_short_title_leaves_short_hypothesis_untouched() -> None:
    assert (
        _short_title("Adversaries dump LSASS memory via comsvcs.dll.")
        == "Adversaries dump LSASS memory via comsvcs.dll."
    )


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
    assert _draft_tags(is_threat_report=True) == [
        "draft",
        "auto-generated",
        "requires-human-review",
    ]


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


def test_next_hunt_id_persists_across_an_emptied_directory(tmp_path: Path) -> None:
    """Regression test for hunt ID reuse.

    The drafts in this workspace are periodically committed to git and
    cleaned off disk. Allocation used to be a pure scan of hunts/, so an
    emptied directory restarted numbering at H-0001 and handed IDs that
    already named a different hunt in git history to brand new drafts --
    two unrelated files both carrying `hunt_id: H-0001`. The persisted
    counter has to outlive the directory being emptied.
    """
    root = tmp_path / "hunts"
    root.mkdir(parents=True)
    for expected in ("H-0001", "H-0002", "H-0003"):
        hunt_id = next_hunt_id(root)
        assert hunt_id == expected
        path = draft_hunt_path(root, hunt_id, datetime.now(UTC))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("stub")

    # Simulate the cleanup: every draft committed away, directory emptied.
    for md in list(root.rglob("H-*.md")):
        md.unlink()
    assert not list(root.rglob("H-*.md"))

    assert next_hunt_id(root) == "H-0004"


def test_next_hunt_id_prefers_on_disk_max_over_a_stale_counter(tmp_path: Path) -> None:
    """A draft added by hand (or by an older hecate-runner that predates the
    counter) sits above the counter's value; it must not be clobbered."""
    root = tmp_path / "hunts"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / ".hunt_id_counter").write_text("3\n")
    (root / "2026" / "Q3" / "H-0042.md").write_text("stub")
    assert next_hunt_id(root) == "H-0043"


def test_next_hunt_id_survives_a_corrupted_counter(tmp_path: Path) -> None:
    """A truncated or hand-edited counter falls back to the on-disk floor
    rather than crashing the cycle."""
    root = tmp_path / "hunts"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / ".hunt_id_counter").write_text("not-a-number")
    (root / "2026" / "Q3" / "H-0008.md").write_text("stub")
    assert next_hunt_id(root) == "H-0009"


def test_next_hunt_id_seeds_from_git_history_on_first_run(tmp_path: Path) -> None:
    """First allocation after the counter was introduced resumes past every
    draft git remembers, including ones already deleted from disk -- the
    committed-then-cleaned drafts a disk scan can no longer see."""
    workspace = tmp_path / "workspace"
    root = workspace / "hunts" / "2026" / "Q3"
    root.mkdir(parents=True)
    git = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    for n in (17, 29, 606):
        (root / f"H-{n:04d}.md").write_text("stub")
    subprocess.run([*git, "add", "-A"], cwd=workspace, check=True, capture_output=True)
    subprocess.run(
        [*git, "commit", "-qm", "drafts"], cwd=workspace, check=True, capture_output=True
    )

    # The cleanup commit: drafts removed from disk, retained only in history.
    for md in list(root.glob("H-*.md")):
        md.unlink()
    subprocess.run([*git, "add", "-A"], cwd=workspace, check=True, capture_output=True)
    subprocess.run(
        [*git, "commit", "-qm", "cleanup"], cwd=workspace, check=True, capture_output=True
    )

    assert next_hunt_id(workspace / "hunts") == "H-0607"


def test_next_hunt_id_outside_a_git_repo_uses_on_disk_max(tmp_path: Path) -> None:
    """A non-git workspace (or a machine without git) still allocates; the
    seed is best-effort and must not fail the cycle."""
    root = tmp_path / "hunts"
    (root / "2026" / "Q3").mkdir(parents=True)
    (root / "2026" / "Q3" / "H-0004.md").write_text("stub")
    assert next_hunt_id(root) == "H-0005"


def test_counter_file_is_readable_like_the_rest_of_the_workspace(tmp_path: Path) -> None:
    """The counter used to inherit mkstemp's owner-only 0o600, unlike every
    other file the workspace holds."""
    root = tmp_path / "hunts"
    root.mkdir(parents=True)
    next_hunt_id(root)
    plain = root / "reference.txt"
    plain.write_text("x")
    counter = root / ".hunt_id_counter"
    assert counter.stat().st_mode & 0o777 == plain.stat().st_mode & 0o777


def test_indicator_sweep_draft_says_research_was_not_needed() -> None:
    """An indicator sweep skips research deliberately, so the draft must not
    report it as "grounding unavailable" -- that reads like a failure. It
    previously linked a research doc whose every section said it had nothing
    to say, under the label "detailed pre-hunt research"."""
    req = DraftHuntRequest(
        hunt_id="H-0611",
        threat_intel="Attributes (42 total): domain (10)",
        hypothesis=HypothesisResult(
            hypothesis="Indicators appear in telemetry.", is_indicator_only=True
        ),
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "an indicator sweep needs no research grounding" in md
    assert "detailed pre-hunt research" not in md
    assert "grounding unavailable" not in md


def test_missing_research_on_a_behavioral_draft_points_reviewer_to_cti() -> None:
    """Without a research document the draft directs review to the CTI."""
    req = DraftHuntRequest(
        hunt_id="H-0612",
        threat_intel="some narrative intel",
        hypothesis=HypothesisResult(hypothesis="Adversaries dump LSASS."),
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "Research Context:** None — review the CTI directly" in md


def test_research_doc_is_linked_as_background_context_when_one_exists() -> None:
    req = DraftHuntRequest(
        hunt_id="H-0613",
        threat_intel="some narrative intel",
        hypothesis=HypothesisResult(hypothesis="Adversaries dump LSASS."),
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
        research_id="R-0042",
    )
    md = render_draft(req)
    assert "See [R-0042](" in md
    assert "for background leads" in md


# --- The embedded CTI must not silently lose evidence ----------------------


class TestEmbeddedCti:
    """`hunt_audit` re-derives a hunt's CTI from the copy embedded in the
    draft, so anything cut here is re-graded UNSUPPORTED later. At the old
    2,000-char cap that turned real C2 domains into reported fabrications on
    H-0007 and H-0010."""

    def test_a_normal_blurb_is_embedded_whole(self) -> None:
        blurb = "OTX Pulse: X\nDescription: prose\nKey indicators:\n  domain: evil-c2.test"
        assert embedded_cti(blurb) == blurb

    def test_a_rich_provider_blurb_survives_intact(self) -> None:
        """The providers cap themselves at ~8k; the embed ceiling is above
        that, so in practice nothing is cut."""
        blurb = "OTX Pulse: X\nKey indicators:\n" + "\n".join(
            f"  domain: host{i}.example-c2.test" for i in range(200)
        )
        assert 2000 < len(blurb) < 10_000
        assert embedded_cti(blurb) == blurb.strip()

    def test_truncation_says_so_rather_than_going_quiet(self) -> None:
        """A silent cut leaves the audit to conclude the missing indicators
        were invented."""
        result = embedded_cti("x" * 12_000)
        assert "characters of CTI omitted" in result
        assert "cannot confirm" in result

    def test_truncation_reports_how_much_was_lost(self) -> None:
        assert "2000 characters" in embedded_cti("x" * 12_000)

    def test_empty_cti_is_handled(self) -> None:
        assert embedded_cti("") == ""


# --- Frontmatter must always be parseable YAML -----------------------------


class TestTitleScalar:
    """H-0002 was drafted from an ESET event titled "MoustachedBouncer:
    Espionage against foreign diplomats". The colon made the frontmatter
    invalid YAML, and `hecate-agent hunt validate` failed on the file -- the
    draft was unreadable by the tooling meant to check it."""

    BREAKER = (
        "Indicators published in MoustachedBouncer: Espionage against foreign "
        "diplomats in Belarus appear in environment telemetry"
    )

    @staticmethod
    def _parse(title_line: str) -> dict:
        return yaml.safe_load("hunt_id: H-0001\n" + title_line + "\nstatus: planning\n")

    def test_a_colon_in_the_hypothesis_stays_valid_yaml(self) -> None:
        parsed = self._parse("title: " + _title_scalar(self.BREAKER))
        assert parsed["title"].startswith("DRAFT - Indicators published in MoustachedBouncer:")

    def test_the_unquoted_form_really_was_broken(self) -> None:
        """Guards the guard: if a bare scalar parsed fine the fix would be
        pointless and this suite would quietly stop meaning anything."""
        with pytest.raises(yaml.YAMLError):
            self._parse("title: DRAFT - " + self.BREAKER)

    def test_embedded_quotes_survive(self) -> None:
        title = 'a "quoted" threat'
        assert self._parse("title: " + _title_scalar(title))["title"].endswith(title)

    def test_a_windows_path_with_backslashes_survives(self) -> None:
        title = "dropped to C:" + chr(92) + "temp" + chr(92)
        assert title in self._parse("title: " + _title_scalar(title))["title"]

    def test_non_ascii_is_not_escaped_away(self) -> None:
        """json.dumps defaults to ensure_ascii=True, which would render a
        title as caf\\u00e9 -- valid YAML, unreadable to a person."""
        title = "caf\u00e9 campaign"
        rendered = _title_scalar(title)
        assert title in rendered
        assert "\\u00e9" not in rendered
        assert self._parse("title: " + rendered)["title"].endswith(title)

    def test_an_empty_hypothesis_still_yields_valid_yaml(self) -> None:
        assert self._parse("title: " + _title_scalar(""))["title"].startswith("DRAFT -")


def test_render_draft_renders_hypothesis_quality_rubric_and_baselines() -> None:
    hyp = HypothesisResult(
        hypothesis="Adversaries dump LSASS memory",
        justification="Common credential theft technique",
        techniques=["T1003.001"],
        expected_malicious="rundll32.exe executing comsvcs.dll against lsass",
        expected_benign="Standard IT diagnostic tasks without LSASS memory dump",
        falsification_criteria="Absence of process access events to lsass across 7 days",
        rubric_score={
            "specificity": 3,
            "testability": 3,
            "falsifiability": 3,
            "relevance": 3,
            "pyramid_level": 3,
            "total": 15,
            "verdict": "GO",
        },
    )
    req = DraftHuntRequest(
        hunt_id="H-0123",
        threat_intel="APT observed dumping LSASS",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "### Hypothesis Quality & Falsification" in md
    assert "- **Rubric Gate Verdict:** `GO` (15/15 points)" in md
    assert "Specificity: 3/3" in md
    assert "Expected Malicious" in md
    assert "rundll32.exe executing comsvcs.dll" in md
    assert "Expected Benign Baseline" in md
    assert "Falsification Criteria" in md


def test_render_draft_omits_hypothesis_quality_when_empty() -> None:
    hyp = HypothesisResult(
        hypothesis="Simple hypothesis without rubric",
        techniques=["T1003.001"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0123",
        threat_intel="test intel",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "### Hypothesis Quality & Falsification" not in md


def test_render_draft_renders_atomic_red_team_validation() -> None:
    hyp = HypothesisResult(
        hypothesis="Adversaries dump LSASS memory",
        techniques=["T1003.001"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0123",
        threat_intel="test intel",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "### Validation Procedure (Atomic Red Team)" in md
    assert "| Technique | Test ID | Procedure / Command | Expected Telemetry |" in md
    assert "`T1003.001`" in md
    assert "procdump.exe" in md


def test_render_draft_renders_soc_triage_playbook() -> None:
    hyp = HypothesisResult(
        hypothesis="Adversaries dump LSASS memory",
        behavior="LSASS memory access via comsvcs.dll MiniDump",
        techniques=["T1003.001"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0123",
        threat_intel="test intel",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
    )
    md = render_draft(req)
    assert "### SOC Responder Triage Playbook (ADS-Lite)" in md
    assert "**Target Technique:** `T1003.001`" in md
    assert "#### 1. Triage & Initial Scoping (First 3 Steps)" in md
    assert "Lineage Verification:" in md
    assert "Identity & Host Scoping:" in md
    assert "Telemetry Correlation:" in md
    assert "#### 2. Containment & IR Escalation" in md
    assert "Immediate Isolation Threshold:" in md
    assert "Credential Invalidation:" in md
    assert "#### 3. Detection Robustness & Evasion Cost" in md
    assert "Observable Robustness:" in md
    assert "**Adversary Evasion Cost:** High" in md


def test_render_draft_renders_cloud_soc_triage_playbook() -> None:
    hyp = HypothesisResult(
        hypothesis="Adversaries abuse OAuth application consent in M365",
        behavior="Illicit OAuth application consent grant",
        techniques=["T1550.001"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0124",
        threat_intel="OAuth consent grant abuse",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
        platforms=["SaaS", "Office365"],
    )
    md = render_draft(req)
    assert "### SOC Responder Triage Playbook (ADS-Lite)" in md
    assert "CloudTrail, Entra, or SaaS audit logs" in md
    assert "STS AssumeRole" in md
    assert "OAuth permissions" in md
    assert "Control Plane / Management Plane audit telemetry" in md


def test_render_draft_renders_linux_soc_triage_playbook() -> None:
    hyp = HypothesisResult(
        hypothesis="Adversaries drop webshells on Linux servers",
        behavior="Webshell execution via cron persistence",
        techniques=["T1059.004"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0125",
        threat_intel="Linux server compromise",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
        platforms=["Linux"],
    )
    md = render_draft(req)
    assert "### SOC Responder Triage Playbook (ADS-Lite)" in md
    assert "/var/log/auth.log" in md
    assert "/dev/shm" in md
    assert "iptables" in md
    assert "eBPF" in md


def test_render_draft_renders_macos_soc_triage_playbook() -> None:
    hyp = HypothesisResult(
        hypothesis="Adversaries execute ClickFix scripts on macOS",
        behavior="Malicious curl paste and Gatekeeper bypass",
        techniques=["T1204.004", "T1553.001"],
    )
    req = DraftHuntRequest(
        hunt_id="H-0126",
        threat_intel="macOS stealer compromise",
        hypothesis=hyp,
        generated_at=datetime(2026, 7, 4, tzinfo=UTC),
        platforms=["macOS"],
    )
    md = render_draft(req)
    assert "### SOC Responder Triage Playbook (ADS-Lite)" in md
    assert "Unified Logging" in md
    assert "LaunchAgents" in md
    assert "Endpoint Security Framework" in md
    # Must avoid Windows artifacts on macOS
    assert "%TEMP%" not in md
    assert "%APPDATA%" not in md
    assert "LSASS" not in md


def test_the_role_table_lists_the_log_sources_the_rules_actually_use(
    sample_hypothesis: HypothesisResult,
) -> None:
    """The table restated the routing and drifted: H-0830's exploitation source
    IPs read "network_connection" (outbound) and bare dual-use paths "proxy"."""
    req = DraftHuntRequest(
        hunt_id="H-0999",
        threat_intel="x",
        hypothesis=sample_hypothesis,
        generated_at=datetime(2026, 10, 23, tzinfo=UTC),
        source_evidence={"url": "https://example.test/report", "chars": 10, "artifacts": []},
        indicator_records=[
            {"value": "45.153.212.101", "type": "ipv4", "role": "inbound", "status": "active"},
            {
                "value": "209.141.43.95",
                "type": "ipv4",
                "role": "download",
                "status": "active",
                "ports": [80],
            },
            {"value": "/vpn/index.html", "type": "url", "role": "dual_use", "status": "active"},
        ],
    )
    table = render_draft(req).split("**Indicators by role**", 1)[1].split("\n\n")[1]
    rows = {
        cells[1].strip(" `"): cells[6].strip()
        for cells in (row.split("|") for row in table.splitlines()[2:])
    }
    assert rows["45.153.212.101"] == "webserver, network_connection"
    assert rows["209.141.43.95"] == "network_connection on 80"
    assert rows["/vpn/index.html"].startswith("none:")
