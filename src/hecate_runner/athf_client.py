"""Subprocess wrapper around the ``athf`` CLI.

Everything that touches ATHF flows through here so we can mock it in tests
and swap out the transport later (e.g., MCP or direct import) without
touching the orchestrator.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class ResearchResult:
    """Parsed output of ``athf research new --output json``."""

    research_id: str = ""
    recommended_hypothesis: str = ""
    related_hunts: list[str] = field(default_factory=list)
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
    # ABLE scoping (see ATHF's templates/HUNT_LOCK.md). Empty when the CLI
    # didn't emit a section for one -- the agent leaves these blank rather
    # than invent specifics not grounded in the CTI it was given, and
    # hunt_writer falls back to the same "[Review CTI and populate]"
    # placeholder it always has for an empty one.
    actor: str = ""
    behavior: str = ""
    location: str = ""
    evidence: str = ""
    # Self-assessed grounding: False means the agent judged the source CTI
    # doesn't actually describe observed/reported adversary behavior (e.g.
    # a vendor/product announcement) and produced a speculative hypothesis
    # anyway rather than refusing outright. Defaults to True (assumed
    # legitimate) -- absence of the "Low Confidence Source:" section in the
    # CLI output (older CLI, or a model that didn't follow the instruction)
    # must not retroactively flag every hunt as low-confidence.
    is_threat_report: bool = True
    low_confidence_reason: str = ""
    # Set when the CLI reports the agent self-assessed its input as a bare
    # indicator list (athf's `is_indicator_only`). This is the backstop path:
    # the orchestrator normally recognises feed dumps itself and builds a
    # sweep draft without an LLM at all, so this only fires when its
    # heuristic missed one and the model caught it.
    is_indicator_only: bool = False
    # ATT&CK-validation notes the CLI prints under a "Warnings:" heading
    # (deprecated IDs remapped, fabricated ones removed). Captured into a
    # field of their own because the section-routing parser below assigns
    # every unrecognised heading's lines to whatever section preceded it --
    # in practice "Evidence:", so these diagnostics were being appended verbatim
    # into the drafted hunt's ABLE Evidence cell.
    warnings: list[str] = field(default_factory=list)
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
        web_search_enabled: bool = True,
    ) -> ResearchResult:
        """Run ``athf research new`` and parse the resulting research ID.

        Grounds the downstream hypothesis in the 5-skill research pipeline
        (system research, adversary tradecraft via web search, telemetry
        mapping, related-work correlation, synthesis) instead of asking the
        model to generate a hypothesis from the raw CTI blob alone.

        web_search_enabled should be set to False for narrative-free CTI
        (e.g. a bare IOC-count blurb with no Description/Summary text) --
        without real narrative to search for, web search grounds against
        whatever else shares the topic's generic/templated title (e.g. other
        days' instances of the same recurring feed digest) and has been
        observed to fabricate malware family names that then propagate into
        the hunt.
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
        if not web_search_enabled:
            cmd.append("--no-web-search")

        stdout = self._run(cmd, timeout_sec=timeout_sec)
        parsed = self._parse_research_output(stdout)
        parsed.raw_output = stdout
        return parsed

    def hypothesis_generator(
        self,
        threat_intel: str,
        research_id: str | None = None,
        timeout_sec: int | None = None,
        indicators_only: bool = False,
    ) -> HypothesisResult:
        """Run ``athf agent run hypothesis-generator`` and parse the output.

        indicators_only should be set for narrative-free CTI (see
        `has_narrative`). Without it the agent's hypothesis template obliges
        the model to name a behavior, and against a bare list of domains it
        invents one -- observed producing "phishing emails" as the delivery
        vector and "stolen credentials ... lateral movement" as follow-on
        activity for feed dumps that described neither.
        """
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
        if indicators_only:
            cmd.append("--indicators-only")

        stdout = self._run(cmd, timeout_sec=timeout_sec)
        parsed = self._parse_hypothesis_output(stdout)
        parsed.raw_output = stdout
        return parsed

    def lookup_technique(
        self, technique_id: str, timeout_sec: int | None = None
    ) -> TechniqueMetadata:
        """Resolve a technique's real tactic(s)/platform(s) via ``athf attack lookup --json``.

        Best-effort and never raises: STIX data may not be installed, the
        technique ID may be unknown/malformed (e.g. a hypothesis-generator
        placeholder), or the call may time out. Any of those just yields a
        not-``found`` result so callers leave the field empty instead of
        guessing — or, as before this existed, hardcoding a tactic that has
        nothing to do with the actual technique.
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

        related_hunts = []
        for source in data.get("related_work", {}).get("sources", []):
            match = re.match(r"hunts/(H-\d+)\.md$", source.get("url", ""))
            if match:
                related_hunts.append(match.group(1))

        return ResearchResult(
            research_id=data.get("research_id", "") or "",
            recommended_hypothesis=data.get("recommended_hypothesis", "") or "",
            related_hunts=related_hunts,
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
            raise AthfError(f"athf exit {result.returncode}: {result.stderr.strip()[:500]}")

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
            "warnings": result.warnings,
        }
        prose_targets: dict[str, str] = {
            "hypothesis": "",
            "justification": "",
            "actor": "",
            "behavior": "",
            "location": "",
            "evidence": "",
            "low_confidence_reason": "",
            "indicator_only_marker": "",
        }

        section_headers = {
            "hypothesis:": "hypothesis",
            "justification:": "justification",
            "mitre att&ck techniques:": "techniques",
            "data sources:": "data_sources",
            "expected observables:": "observables",
            "known false positives:": "false_positives",
            "actor:": "actor",
            "behavior:": "behavior",
            "location:": "location",
            "evidence:": "evidence",
            "low confidence source:": "low_confidence_reason",
            "indicator-only source:": "indicator_only_marker",
            "warnings:": "warnings",
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
        result.actor = prose_targets["actor"]
        result.behavior = prose_targets["behavior"]
        result.location = prose_targets["location"]
        result.evidence = prose_targets["evidence"]
        # The CLI only prints a "Low Confidence Source:" section at all when
        # is_threat_report is False (see _display_hypothesis_generator_result)
        # -- its mere presence with non-empty content is the signal, same as
        # how absence must leave HypothesisResult's True default untouched.
        if prose_targets["low_confidence_reason"]:
            result.is_threat_report = False
            result.low_confidence_reason = prose_targets["low_confidence_reason"]
        # Same convention: the CLI prints this section only when the agent
        # self-assessed the source as indicator-only, so its presence is the
        # signal and its absence must leave the False default alone.
        result.is_indicator_only = bool(prose_targets["indicator_only_marker"])
        return result
