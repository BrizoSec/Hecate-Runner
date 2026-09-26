"""HecateClient.research_new: what it sends to Hecate and reads back."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import hecate_agent.api
import pytest

from hecate_runner.hecate_client import HecateClient

_NO_BEHAVIOR = "No telemetry mapped - the source describes no behavior to detect"


def _output(telemetry_findings: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        research_id="R-0001",
        recommended_hypothesis="",
        related_work=SimpleNamespace(sources=[]),
        telemetry_mapping=SimpleNamespace(key_findings=telemetry_findings),
    )


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> HecateClient:
    c = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)
    monkeypatch.setattr(c, "_with_context", lambda func, *a, **kw: func(*a, **kw))
    return c


def test_source_context_is_forwarded(client: HecateClient, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def generate_research(
        topic, technique, depth, web_search_enabled, workspace, source_context=None
    ):  # type: ignore[no-untyped-def]
        seen["source_context"] = source_context
        return _output(["process.cmd_line: shell"]), Path("r.md")

    monkeypatch.setattr(hecate_agent.api, "generate_research", generate_research)
    client.research_new(topic="PolinRider", source_context="font-file payloads")
    assert seen["source_context"] == "font-file payloads"


def test_a_hecate_without_source_context_still_researches(
    client: HecateClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hecate versions independently; an older one must not fail the cycle."""

    def generate_research(topic, technique, depth, web_search_enabled, workspace):  # type: ignore[no-untyped-def]
        return _output([]), Path("r.md")

    monkeypatch.setattr(hecate_agent.api, "generate_research", generate_research)
    assert client.research_new(topic="t", source_context="body").research_id == "R-0001"


@pytest.mark.parametrize(
    ("findings", "expected"),
    [
        ([_NO_BEHAVIOR], False),
        (["process.cmd_line: shell"], True),
        # Unreadable is not a verdict: absence must never park an item.
        ([], True),
    ],
)
def test_describes_behavior_reads_the_telemetry_verdict(
    client: HecateClient, monkeypatch: pytest.MonkeyPatch, findings: list[str], expected: bool
) -> None:
    monkeypatch.setattr(
        hecate_agent.api, "generate_research", lambda **kw: (_output(findings), Path("r.md"))
    )
    assert client.research_new(topic="t").describes_behavior is expected


# --- sigma_generator ---------------------------------------------------------

_ALL_REJECTED = (
    "Sigma generation failed: no log source produced a valid rule: "
    "file_event: selections match only '.so', which names no particular file, process or host; "
    "process_creation: detection matches on '--query=example.com', which contains the placeholder 'example.com'"
)


def test_every_rule_rejected_is_an_outcome_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """H-0017: all proposed rules failed validation, and the cycle logged an
    ERROR with a traceback before creating its draft normally."""

    def generate_sigma(payload, out_dir, hunt_id):  # type: ignore[no-untyped-def]
        raise RuntimeError(_ALL_REJECTED)

    monkeypatch.setattr(hecate_agent.api, "generate_sigma", generate_sigma)
    client = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)

    result = client.sigma_generator({"hunt_id": "H-0017"}, tmp_path / "q")

    assert result.success is False
    assert result.rules == []
    assert result.rejected == [
        "file_event: selections match only '.so', which names no particular file, process or host",
        "process_creation: detection matches on '--query=example.com', which contains the placeholder 'example.com'",
    ]
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_a_real_sigma_failure_still_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from hecate_runner.hecate_client import HecateError

    def generate_sigma(payload, out_dir, hunt_id):  # type: ignore[no-untyped-def]
        raise RuntimeError("Sigma generation failed: Sigma generation requires an LLM")

    monkeypatch.setattr(hecate_agent.api, "generate_sigma", generate_sigma)
    client = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)

    with pytest.raises(HecateError):
        client.sigma_generator({"hunt_id": "H-0017"}, tmp_path / "q")
