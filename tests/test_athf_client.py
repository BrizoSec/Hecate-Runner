"""Tests for the athf subprocess wrapper and the hypothesis-output parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from sec7669.athf_client import AthfClient, AthfError

# Real `athf research new --output json` prints a human-readable progress
# banner to stdout *before* the JSON payload, even in JSON mode — the parser
# has to find and skip past it.
SAMPLE_RESEARCH_OUTPUT = """
Starting Research: R-0004
Topic: Scheduled task abuse for persistence
Depth: basic (~5 min)
Technique: T1053.005

{
  "research_id": "R-0004",
  "topic": "Scheduled task abuse for persistence",
  "recommended_hypothesis": "Adversaries create scheduled tasks for persistence.",
  "mitre_techniques": ["T1053.005"]
}
"""

SAMPLE_OUTPUT = """
✓ Hypothesis generated successfully

Hypothesis:
  Adversaries use LSASS memory dumping via direct system call techniques.

Justification:
  This targets a specific technique that can evade EDR.

MITRE ATT&CK Techniques:
  • T1003.001

Data Sources:
  • EDR telemetry
  • SIEM logs

Expected Observables:
  • Process execution with suspicious access masks to lsass.exe
  • Network connections associated with known malicious IPs

Known False Positives:
  • System maintenance tasks
  • Administrative tool usage
"""


def test_parse_full_output() -> None:
    result = AthfClient._parse_hypothesis_output(SAMPLE_OUTPUT)
    assert "LSASS memory dumping" in result.hypothesis
    assert "EDR" in result.justification
    assert result.techniques == ["T1003.001"]
    assert result.data_sources == ["EDR telemetry", "SIEM logs"]
    assert len(result.observables) == 2
    assert result.false_positives == ["System maintenance tasks", "Administrative tool usage"]
    assert not result.is_empty


def test_parse_empty_output() -> None:
    result = AthfClient._parse_hypothesis_output("")
    assert result.is_empty
    assert result.techniques == []


def test_parse_output_no_lists() -> None:
    text = "Hypothesis:\n  Just a hypothesis with no lists at all.\n"
    result = AthfClient._parse_hypothesis_output(text)
    assert "hypothesis with no lists" in result.hypothesis
    assert result.techniques == []


def test_check_installed_missing_binary(tmp_path: Path) -> None:
    client = AthfClient(
        athf_bin=tmp_path / "does_not_exist",
        workspace=tmp_path,
    )
    with pytest.raises(AthfError, match="not found"):
        client.check_installed()


def test_check_installed_ok(athf_client: AthfClient) -> None:
    athf_client.check_installed()  # no raise


def _make_fake_athf(tmp_path: Path, script: str) -> Path:
    """Write an executable shell script that behaves like athf for one test."""
    fake = tmp_path / "fake_athf.sh"
    fake.write_text(script)
    fake.chmod(0o755)
    return fake


def test_run_captures_stdout(athf_client: AthfClient, tmp_path: Path) -> None:
    fake = _make_fake_athf(tmp_path, "#!/bin/sh\nprintf '%s' 'hello from athf'\n")
    athf_client.athf_bin = fake
    stdout = athf_client._run([str(fake), "--noop"])
    assert stdout == "hello from athf"


def test_run_raises_on_nonzero(athf_client: AthfClient, tmp_path: Path) -> None:
    fake = _make_fake_athf(tmp_path, "#!/bin/sh\necho boom >&2; exit 3\n")
    athf_client.athf_bin = fake
    with pytest.raises(AthfError, match="exit 3"):
        athf_client._run([str(fake)])


def test_run_raises_on_timeout(athf_client: AthfClient, tmp_path: Path) -> None:
    fake = _make_fake_athf(tmp_path, "#!/bin/sh\nsleep 5\n")
    athf_client.athf_bin = fake
    with pytest.raises(AthfError, match="timed out"):
        athf_client._run([str(fake)], timeout_sec=1)


def test_hypothesis_generator_end_to_end(
    athf_client: AthfClient, tmp_path: Path
) -> None:
    fake = _make_fake_athf(
        tmp_path,
        f"#!/bin/sh\ncat <<'END'\n{SAMPLE_OUTPUT}\nEND\n",
    )
    athf_client.athf_bin = fake
    result = athf_client.hypothesis_generator("some intel")
    assert result.techniques == ["T1003.001"]
    assert "LSASS" in result.hypothesis


def test_parse_research_output_skips_progress_banner() -> None:
    result = AthfClient._parse_research_output(SAMPLE_RESEARCH_OUTPUT)
    assert result.research_id == "R-0004"
    assert "scheduled tasks" in result.recommended_hypothesis
    assert not result.is_empty


def test_parse_research_output_empty() -> None:
    result = AthfClient._parse_research_output("")
    assert result.is_empty
    assert result.research_id == ""


def test_parse_research_output_malformed_json_is_non_fatal() -> None:
    result = AthfClient._parse_research_output("Starting Research: R-0001\n{not valid json")
    assert result.is_empty


def test_research_new_end_to_end(athf_client: AthfClient, tmp_path: Path) -> None:
    fake = _make_fake_athf(
        tmp_path,
        f"#!/bin/sh\ncat <<'END'\n{SAMPLE_RESEARCH_OUTPUT}\nEND\n",
    )
    athf_client.athf_bin = fake
    result = athf_client.research_new(topic="Scheduled task abuse", technique="T1053.005")
    assert result.research_id == "R-0004"


def test_research_new_builds_expected_command(
    athf_client: AthfClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(self: AthfClient, cmd: list[str], *, timeout_sec: int | None = None) -> str:
        captured["cmd"] = cmd
        return SAMPLE_RESEARCH_OUTPUT

    monkeypatch.setattr(AthfClient, "_run", fake_run)
    athf_client.research_new(topic="Scheduled task abuse", technique="T1053.005", depth="basic")

    cmd = captured["cmd"]
    assert "research" in cmd and "new" in cmd
    assert cmd[cmd.index("--topic") + 1] == "Scheduled task abuse"
    assert cmd[cmd.index("--technique") + 1] == "T1053.005"
    assert cmd[cmd.index("--depth") + 1] == "basic"
    assert cmd[cmd.index("--output") + 1] == "json"


def test_research_new_omits_technique_when_none(
    athf_client: AthfClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(self: AthfClient, cmd: list[str], *, timeout_sec: int | None = None) -> str:
        captured["cmd"] = cmd
        return SAMPLE_RESEARCH_OUTPUT

    monkeypatch.setattr(AthfClient, "_run", fake_run)
    athf_client.research_new(topic="Scheduled task abuse")

    assert "--technique" not in captured["cmd"]
