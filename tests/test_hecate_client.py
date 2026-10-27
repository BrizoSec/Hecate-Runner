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


_REJECTED = [
    "file_event: selections match only '.so', which names no particular file, process or host",
    "process_creation: detection matches on '--query=example.com', which contains the placeholder 'example.com'",
]


def _metrics_result(
    *, rejected: list[str], error: str | None, success: bool
) -> tuple[Any, list[Path], dict[str, Any]]:
    """What Core's generate_sigma_with_metrics returns: output, files, metadata."""
    from hecate_agent.agents.llm.sigma_generator import SigmaGenerationOutput

    output = SigmaGenerationOutput(logsources_considered=["file_event"], rejected=rejected)
    return output, [], {"success": success, "error": error, "warnings": []}


# --- Core with generate_sigma_with_metrics (the path the client prefers) -----------------


@pytest.mark.parametrize("metrics_api", [True, False])
def test_sigma_paths_ignore_interleaved_native_query_files(
    client, tmp_path, monkeypatch, metrics_api
):
    from hecate_agent.agents.llm.sigma_generator import SigmaGenerationOutput, SigmaRule

    output = SigmaGenerationOutput(
        logsources_considered=["dns_query", "file_event"],
        rules=[
            SigmaRule(logsource_category="dns_query", title="DNS", rule_yaml="title: DNS"),
            SigmaRule(logsource_category="file_event", title="File", rule_yaml="title: File"),
        ],
    )
    paths = [tmp_path / name for name in ("dns.yml", "dns.kql", "dns.leql", "file.yml", "file.kql")]
    if metrics_api:
        monkeypatch.setattr(
            hecate_agent.api,
            "generate_sigma_with_metrics",
            lambda **kwargs: (output, paths, {"success": True}),
        )
    else:
        monkeypatch.delattr(hecate_agent.api, "generate_sigma_with_metrics")
        monkeypatch.setattr(hecate_agent.api, "generate_sigma", lambda **kwargs: (output, paths))
    result = client.sigma_generator({"hunt_id": "H-TEST"}, tmp_path)
    assert [r["path"] for r in result.rules] == [
        str(tmp_path / "dns.yml"),
        str(tmp_path / "file.yml"),
    ]
    assert result.files == paths


def test_every_rule_rejected_is_an_outcome_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """H-0017: all proposed rules failed validation, and the cycle logged an
    ERROR with a traceback before creating its draft normally."""
    monkeypatch.setattr(
        hecate_agent.api,
        "generate_sigma_with_metrics",
        lambda payload, out_dir, hunt_id: _metrics_result(
            rejected=_REJECTED, error="no log source produced a valid rule", success=False
        ),
    )
    client = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)

    result = client.sigma_generator({"hunt_id": "H-0017"}, tmp_path / "q")

    assert result.success is False
    assert result.rules == []
    assert result.rejected == _REJECTED
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_a_real_sigma_failure_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With metrics, Core returns failures in metadata; the orchestrator logs
    them as a warning and keeps the draft's placeholder query section."""
    monkeypatch.setattr(
        hecate_agent.api,
        "generate_sigma_with_metrics",
        lambda payload, out_dir, hunt_id: _metrics_result(
            rejected=[], error="Sigma generation requires an LLM", success=False
        ),
    )
    client = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)

    result = client.sigma_generator({"hunt_id": "H-0017"}, tmp_path / "q")

    assert result.success is False
    assert result.error == "Sigma generation requires an LLM"
    assert result.rules == []


# --- An older Core without it: the generate_sigma fallback -------------------------------


def test_fallback_every_rule_rejected_is_an_outcome_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def generate_sigma(payload, out_dir, hunt_id):  # type: ignore[no-untyped-def]
        raise RuntimeError(_ALL_REJECTED)

    monkeypatch.delattr(hecate_agent.api, "generate_sigma_with_metrics", raising=False)
    monkeypatch.setattr(hecate_agent.api, "generate_sigma", generate_sigma)
    client = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)

    result = client.sigma_generator({"hunt_id": "H-0017"}, tmp_path / "q")

    assert result.success is False
    assert result.rules == []
    assert result.rejected == _REJECTED
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


def test_fallback_a_real_sigma_failure_still_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hecate_runner.hecate_client import HecateError

    def generate_sigma(payload, out_dir, hunt_id):  # type: ignore[no-untyped-def]
        raise RuntimeError("Sigma generation failed: Sigma generation requires an LLM")

    monkeypatch.delattr(hecate_agent.api, "generate_sigma_with_metrics", raising=False)
    monkeypatch.setattr(hecate_agent.api, "generate_sigma", generate_sigma)
    client = HecateClient(hecate_bin=Path("hecate-agent"), workspace=tmp_path)

    with pytest.raises(HecateError):
        client.sigma_generator({"hunt_id": "H-0017"}, tmp_path / "q")
