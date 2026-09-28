"""The decision trail: one readable line per stage of a cycle, and `watch`."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from hecate_runner.cli import _watch_line, app
from hecate_runner.config import Settings
from hecate_runner.cti import FileQueueProvider
from hecate_runner.hecate_client import ResearchResult
from hecate_runner.orchestrator import Orchestrator
from hecate_runner.trail import LOGGER_NAME, clip, counts, listing

_STAGE = re.compile(r"^\[(\w{6}) \+\s*[\d.]+s\] (\w+)")


def _trail(caplog: pytest.LogCaptureFixture) -> list[tuple[str, str, str]]:
    """(cycle id, stage, full message) for every trail line captured."""
    found = []
    for record in caplog.records:
        if record.name != LOGGER_NAME:
            continue
        message = record.getMessage()
        match = _STAGE.match(message)
        assert match, message
        found.append((match.group(1), match.group(2), message))
    return found


def test_a_drafted_cycle_logs_every_stage_in_order(
    settings: Settings,
    file_queue_with_cti: FileQueueProvider,
    mock_hecate: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=file_queue_with_cti).run_once()

    trail = _trail(caplog)
    stages = list(dict.fromkeys(stage for _, stage, _ in trail))
    assert stages[:10] == [
        "start",
        "intake",
        "triage",
        "quota",
        "route",
        "source",
        "research",
        "hypothesis",
        "techniques",
        "scope",
    ]
    assert {"grounding", "write"} <= set(stages)
    assert stages[-1] == "done"
    # One cycle, one ID.
    assert len({cycle for cycle, _, _ in trail}) == 1
    done = trail[-1][2]
    assert "draft_created -> H-0001" in done


def test_a_parked_item_says_why(
    settings: Settings, workspace: Path, mock_hecate: MagicMock, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    mock_hecate.research_new.return_value = ResearchResult(
        research_id="R-0005", describes_behavior=False
    )
    provider = FileQueueProvider(queue_dir=workspace / "cti_queue")
    provider.ensure_dirs()
    (workspace / "cti_queue" / "next.txt").write_text(
        "RSS: Opinion\nSource: x.example\nSummary: AI models are restrictive for defenders.\n"
        "Link: https://x.example/p"
    )
    Orchestrator(settings=settings, hecate=mock_hecate, cti_provider=provider).run_once()

    messages = [m for _, _, m in _trail(caplog)]
    assert any("describes adversary behavior: NO" in m for m in messages)
    assert any("park: research R-0005 found no adversary behavior" in m for m in messages)
    assert "parked_after_research" in messages[-1]


def test_helpers_render_compactly() -> None:
    assert listing([]) == "none"
    assert listing(["T1036", "T1113"]) == "T1036, T1113"
    assert counts({"IPv4": ["a", "b"], "domain": ["c"]}) == "IPv4 2, domain 1"
    assert clip("a  b\nc") == "a b c"
    assert len(clip("x" * 300, 50)) == 50


class TestWatchLine:
    TRAIL = (
        "2026-09-24 02:15:24,684 [INFO] hecate_runner.trail: "
        "[c7f3a1 +  84.2s] research   R-0012 done in 81s"
    )
    NOISE = "2026-09-24 02:15:24,684 [INFO] hecate_runner.orchestrator: Wrote draft"
    WARN = "2026-09-24 02:15:24,684 [WARNING] hecate_runner.cti.multi: misp failed"
    CORE = "2026-09-24 02:15:24,684 [INFO] hecate_agent.agents.llm.hypothesis_generator: offered"

    def test_trail_lines_lose_the_logger_prefix(self) -> None:
        assert (
            _watch_line(self.TRAIL, False)
            == "02:15:24 [c7f3a1 +  84.2s] research   R-0012 done in 81s"
        )

    def test_other_info_is_hidden_unless_all(self) -> None:
        assert _watch_line(self.NOISE, False) is None
        assert "Wrote draft" in (_watch_line(self.NOISE, True) or "")

    def test_warnings_and_hecate_info_are_shown(self) -> None:
        assert "misp failed" in (_watch_line(self.WARN, False) or "")
        assert (_watch_line(self.CORE, False) or "").endswith("hecate: offered")

    def test_traceback_lines_only_with_all(self) -> None:
        assert _watch_line("  File x.py, line 3", False) is None
        assert _watch_line("  File x.py, line 3", True) == "  File x.py, line 3"


def test_watch_prints_recent_trail_without_following(
    workspace: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HECATE_WORKSPACE", str(workspace))
    log_file = Settings().log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.write_text(
        "\n".join([TestWatchLine.NOISE, TestWatchLine.TRAIL, TestWatchLine.WARN]) + "\n"
    )

    result = CliRunner().invoke(app, ["watch", "--no-follow"])

    assert result.exit_code == 0
    assert "research   R-0012 done in 81s" in result.output
    assert "misp failed" in result.output
    assert "Wrote draft" not in result.output
