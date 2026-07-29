"""Subprocess wrapper around the ``athf`` CLI.

Everything that touches ATHF flows through here so we can mock it in tests
and swap out the transport later (e.g., MCP or direct import) without
touching the orchestrator.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class ResearchResult:
    """Parsed output of ``athf research new --output json``."""

    research_id: str = ""
    recommended_hypothesis: str = ""
    raw_output: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.research_id.strip()


@dataclass
class HypothesisResult:
    """Parsed output of ``athf agent run hypothesis-generator``."""

    hypothesis: str = ""
    justification: str = ""
    techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    observables: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    raw_output: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.hypothesis.strip()


@dataclass
class TechniqueMetadata:
    """Parsed output of ``athf attack lookup <id> --json``."""

    technique_id: str = ""
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    found: bool = False


class AthfError(RuntimeError):
    """Raised when the athf CLI fails or returns unexpected output."""


class AthfClient:
    """Thin wrapper: locate the athf binary, run subprocesses, parse output."""

    def __init__(
        self,
        athf_bin: Path,
        workspace: Path,
        env_overrides: dict[str, str] | None = None,
        default_timeout_sec: int = 600,
    ):
        self.athf_bin = athf_bin
        self.workspace = workspace
        self.env_overrides = env_overrides or {}
        self.default_timeout_sec = default_timeout_sec

    def check_installed(self) -> None:
        """Raise if the athf binary is missing or not executable."""
        if not self.athf_bin.exists():
            raise AthfError(f"athf binary not found at {self.athf_bin}")
        if not os.access(self.athf_bin, os.X_OK):
            raise AthfError(f"athf binary at {self.athf_bin} is not executable")

    # --- Public API --------------------------------------------------------

    def research_new(
        self,
        topic: str,
        technique: str | None = None,
        depth: str = "basic",
        timeout_sec: int | None = None,
    ) -> ResearchResult:
        """Run ``athf research new`` and parse the resulting research ID.

        Grounds the downstream hypothesis in the 5-skill research pipeline
        (system research, adversary tradecraft via web search, telemetry
        mapping, related-work correlation, synthesis) instead of asking the
        model to generate a hypothesis from the raw CTI blob alone.
        """
        cmd = [
            str(self.athf_bin),
            "research",
            "new",
            "--topic",
            topic,
            "--depth",
            depth,
            "--output",
            "json",
        ]
        if technique:
            cmd.extend(["--technique", technique])

        stdout = self._run(cmd, timeout_sec=timeout_sec)
        parsed = self._parse_research_output(stdout)
        parsed.raw_output = stdout
        return parsed

    def hypothesis_generator(
        self,
        threat_intel: str,
        research_id: str | None = None,
        timeout_sec: int | None = None,
    ) -> HypothesisResult:
        """Run ``athf agent run hypothesis-generator`` and parse the output."""
        cmd = [
            str(self.athf_bin),
            "agent",
            "run",
            "hypothesis-generator",
            "--threat-intel",
            threat_intel,
        ]
        if research_id:
            cmd.extend(["--research", research_id])

        stdout = self._run(cmd, timeout_sec=timeout_sec)
        parsed = self._parse_hypothesis_output(stdout)
        parsed.raw_output = stdout
        return parsed

    def lookup_technique(self, technique_id: str, timeout_sec: int | None = None) -> TechniqueMetadata:
        """Resolve a technique's real tactic(s)/platform(s) via ``athf attack lookup --json``.

        Best-effort and never raises: STIX data may not be installed, the
        technique ID may be unknown/malformed (e.g. a hypothesis-generator
        placeholder), or the call may time out. Any of those just yields a
        not-``found`` result so callers fall back to an explicit
        "unclassified" placeholder instead of guessing — or, as before this
        existed, hardcoding a tactic that has nothing to do with the actual
        technique.
        """
        cmd = [str(self.athf_bin), "attack", "lookup", technique_id, "--json"]
        try:
            stdout = self._run(cmd, timeout_sec=timeout_sec)
        except AthfError as exc:
            log.warning("athf attack lookup %s failed: %s", technique_id, exc)
            return TechniqueMetadata(technique_id=technique_id)

        try:
            data = json.loads(stdout.strip())
        except json.JSONDecodeError:
            log.warning("athf attack lookup %s produced non-JSON output", technique_id)
            return TechniqueMetadata(technique_id=technique_id)

        if "error" in data:
            return TechniqueMetadata(technique_id=technique_id)

        return TechniqueMetadata(
            technique_id=data.get("id") or technique_id,
            tactics=list(data.get("tactics", [])),
            platforms=list(data.get("platforms", [])),
            found=True,
        )

    # --- Internal ----------------------------------------------------------

    @staticmethod
    def _parse_research_output(text: str) -> ResearchResult:
        """Extract the JSON object from ``athf research new --output json``.

        The CLI prints a human-readable progress banner ("Starting Research:
        R-000X ...") to stdout *before* the JSON payload even in JSON mode,
        so we can't ``json.loads`` the whole thing directly — find where the
        JSON object starts and parse from there.
        """
        start = text.find("{")
        if start == -1:
            log.warning("athf research new produced no JSON object in output")
            return ResearchResult()

        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            log.warning("Failed to parse athf research new JSON output: %s", exc)
            return ResearchResult()

        return ResearchResult(
            research_id=data.get("research_id", "") or "",
            recommended_hypothesis=data.get("recommended_hypothesis", "") or "",
        )

    def _run(self, cmd: list[str], *, timeout_sec: int | None = None) -> str:
        timeout = timeout_sec or self.default_timeout_sec

        env = {**os.environ, **self.env_overrides}
        env["PATH"] = f"{self.athf_bin.parent}{os.pathsep}{env.get('PATH', '')}"

        preview = " ".join(cmd[:5]) + (" ..." if len(cmd) > 5 else "")
        log.info("athf exec: %s (timeout=%ds)", preview, timeout)

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.workspace),
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AthfError(f"athf call timed out after {timeout}s: {preview}") from exc
        except FileNotFoundError as exc:
            raise AthfError(f"athf binary missing at {self.athf_bin}") from exc

        if result.returncode != 0:
            log.error(
                "athf failed rc=%d stderr=%s",
                result.returncode,
                result.stderr[:500],
            )
            raise AthfError(
                f"athf exit {result.returncode}: {result.stderr.strip()[:500]}"
            )

        return result.stdout

    @staticmethod
    def _parse_hypothesis_output(text: str) -> HypothesisResult:
        """Best-effort parse of the human-readable hypothesis-generator output.

        The CLI prints sections like:
            Hypothesis:
              <text>
            Justification:
              <text>
            MITRE ATT&CK Techniques:
              • T1003.001
        We walk line-by-line and route content into the current section.
        """
        result = HypothesisResult()
        section: str | None = None
        list_targets = {
            "techniques": result.techniques,
            "data_sources": result.data_sources,
            "observables": result.observables,
            "false_positives": result.false_positives,
        }
        prose_targets: dict[str, str] = {"hypothesis": "", "justification": ""}

        section_headers = {
            "hypothesis:": "hypothesis",
            "justification:": "justification",
            "mitre att&ck techniques:": "techniques",
            "data sources:": "data_sources",
            "expected observables:": "observables",
            "known false positives:": "false_positives",
        }

        for raw_line in text.splitlines():
            stripped = raw_line.strip()

            # Section switch?
            lowered = stripped.lower()
            if lowered in section_headers:
                section = section_headers[lowered]
                continue

            if not stripped or section is None:
                continue

            if section in list_targets:
                if stripped.startswith(("-", "*", "•")):
                    list_targets[section].append(stripped.lstrip("-*• ").strip())
            elif section in prose_targets:
                prose_targets[section] = (prose_targets[section] + " " + stripped).strip()

        result.hypothesis = prose_targets["hypothesis"]
        result.justification = prose_targets["justification"]
        return result
