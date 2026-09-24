"""Python API client wrapping the hecate_agent package."""

from __future__ import annotations

import importlib.util
import inspect
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


#: Hecate's research writes this as skill 3's only finding when it judges the
#: source to describe no adversary behavior (``_NO_TELEMETRY_KEY_FINDING``).
_NO_BEHAVIOR_FINDING = "No telemetry mapped - the source describes no behavior"


@dataclass
class ResearchResult:
    research_id: str = ""
    recommended_hypothesis: str = ""
    related_hunts: list[str] = field(default_factory=list)
    raw_output: str = ""
    #: False when research's telemetry skill concluded the source describes
    #: no adversary behavior at all -- its judgement of the item, not of the
    #: web results. True whenever that cannot be read, so absence never parks.
    describes_behavior: bool = True

    @property
    def is_empty(self) -> bool:
        return not self.research_id.strip()


@dataclass
class HypothesisResult:
    hypothesis: str = ""
    justification: str = ""
    techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    observables: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    actor: str = ""
    behavior: str = ""
    location: str = ""
    evidence: str = ""
    is_threat_report: bool = True
    low_confidence_reason: str = ""
    is_indicator_only: bool = False
    warnings: list[str] = field(default_factory=list)
    raw_output: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.hypothesis.strip()


@dataclass
class TechniqueMetadata:
    technique_id: str = ""
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    found: bool = False
    superseded_from: str = ""
    name: str = ""
    #: Name of the parent technique when this is a sub-technique. Sub-technique
    #: names are often narrower than the behaviour a source describes --
    #: T1036.005 is "Match Legitimate Resource Name or Location"; the word a
    #: report actually uses is the parent's, "Masquerading".
    parent_name: str = ""


class HecateError(RuntimeError):
    pass


@dataclass
class SigmaResult:
    success: bool
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    logsources_considered: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)


class HecateClient:
    def __init__(
        self,
        hecate_bin: Path,
        workspace: Path,
        env_overrides: dict[str, str] | None = None,
        default_timeout_sec: int = 600,
    ):
        self.hecate_bin = hecate_bin
        self.workspace = workspace
        self.env_overrides = env_overrides or {}
        self.default_timeout_sec = default_timeout_sec
        self._workspace_env: dict[str, str | None] | None = None

    def check_installed(self) -> None:
        if importlib.util.find_spec("hecate_agent") is None:
            raise HecateError("hecate_agent Python package not found.")

    def _with_context(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        original_cwd = os.getcwd()
        original_env = os.environ.copy()
        try:
            os.chdir(self.workspace)
            # 1. Load the workspace's .env so we pick up HECATE_LLM_MODEL, etc.
            # Cache it to avoid excessive disk I/O when called in loops.
            if self._workspace_env is None:
                from dotenv import dotenv_values

                self._workspace_env = dotenv_values(self.workspace / ".env")

            for k, v in self._workspace_env.items():
                if v is not None:
                    os.environ[k] = v

            # 2. Apply runner overrides on top
            os.environ.update(self.env_overrides)

            return func(*args, **kwargs)
        except Exception as exc:
            log.exception(f"Hecate API call failed: {exc}")
            raise HecateError(f"Hecate API error: {exc}") from exc
        finally:
            os.chdir(original_cwd)
            os.environ.clear()
            os.environ.update(original_env)

    def research_new(
        self,
        topic: str,
        technique: str | None = None,
        depth: str = "basic",
        timeout_sec: int | None = None,
        web_search_enabled: bool = True,
        source_context: str | None = None,
    ) -> ResearchResult:
        from hecate_agent.api import generate_research

        kwargs: dict[str, Any] = {}
        # Hecate versions independently; one predating `source_context`
        # researches from the topic alone rather than failing the cycle.
        if source_context and "source_context" in inspect.signature(generate_research).parameters:
            kwargs["source_context"] = source_context
        output, _ = self._with_context(
            generate_research,
            topic=topic,
            technique=technique,
            depth=depth,
            web_search_enabled=web_search_enabled,
            workspace=self.workspace,
            **kwargs,
        )
        related_hunts = []
        for source in output.related_work.sources:
            if (
                "url" in source
                and source["url"].startswith("hunts/H-")
                and source["url"].endswith(".md")
            ):
                related_hunts.append(source["url"].replace("hunts/", "").replace(".md", ""))
        telemetry = getattr(output, "telemetry_mapping", None)
        telemetry_findings = [str(f) for f in (getattr(telemetry, "key_findings", None) or [])]
        return ResearchResult(
            research_id=output.research_id,
            recommended_hypothesis=output.recommended_hypothesis or "",
            related_hunts=related_hunts,
            raw_output="",
            describes_behavior=not (
                telemetry_findings
                and all(f.startswith(_NO_BEHAVIOR_FINDING) for f in telemetry_findings)
            ),
        )

    def hypothesis_generator(
        self,
        threat_intel: str,
        research_id: str | None = None,
        timeout_sec: int | None = None,
        indicators_only: bool = False,
    ) -> HypothesisResult:
        from hecate_agent.api import generate_hypothesis

        output = self._with_context(
            generate_hypothesis,
            threat_intel=threat_intel,
            research_id=research_id,
            indicators_only=indicators_only,
            workspace=self.workspace,
        )
        return HypothesisResult(
            hypothesis=output.hypothesis,
            justification=output.justification,
            techniques=output.mitre_techniques,
            data_sources=output.data_sources,
            observables=output.expected_observables,
            false_positives=output.known_false_positives,
            actor=output.actor or "",
            behavior=output.behavior or "",
            location=output.location or "",
            evidence=output.evidence or "",
            is_threat_report=output.is_threat_report,
            low_confidence_reason=output.low_confidence_reason or "",
            is_indicator_only=output.is_indicator_only,
            warnings=[],
            raw_output="",
        )

    def sigma_generator(
        self,
        payload: dict[str, Any],
        out_dir: Path,
        timeout_sec: int | None = None,
    ) -> SigmaResult:
        from hecate_agent.api import generate_sigma

        output, files = self._with_context(
            generate_sigma,
            payload=payload,
            out_dir=out_dir,
            hunt_id=payload.get("hunt_id"),
        )
        rules = [
            {
                "logsource_category": r.logsource_category,
                "title": r.title,
                "level": r.level,
                "techniques": r.techniques,
                "rule_yaml": r.rule_yaml,
            }
            for r in output.rules
        ]
        return SigmaResult(
            success=True,
            error=None,
            warnings=[],
            logsources_considered=output.logsources_considered,
            rejected=output.rejected,
            files=files,
            rules=rules,
        )

    def lookup_technique(
        self,
        technique_id: str,
        timeout_sec: int | None = None,
    ) -> TechniqueMetadata:
        from hecate_agent.api import lookup_technique

        try:
            data = self._with_context(lookup_technique, technique_id=technique_id)
        except RuntimeError as exc:
            if "stix_unavailable" in str(exc):
                return TechniqueMetadata()
            raise HecateError(f"lookup failed: {exc}") from exc
        resolved_id = data.get("technique_id", "")
        return TechniqueMetadata(
            technique_id=resolved_id,
            tactics=data.get("tactics", []),
            platforms=data.get("platforms", []),
            found=data.get("found", False),
            superseded_from=data.get("superseded_from", ""),
            name=data.get("name", ""),
            parent_name=self._parent_name(resolved_id),
        )

    def candidate_techniques(self, text: str) -> list[tuple[str, str]]:
        """(ID, name) for ATT&CK techniques the text names as a phrase.

        Deterministic matching in Hecate (``core.technique_candidates``), not
        a model call. Returns nothing -- rather than failing the cycle -- on a
        Hecate that predates the module or when ATT&CK data cannot be read.
        """
        try:
            from hecate_agent.core.technique_candidates import candidate_techniques
        except ImportError:
            return []
        try:
            found = self._with_context(candidate_techniques, text)
        except Exception as exc:  # candidates are an aid; never fatal
            log.warning("Candidate technique matching failed (%s); continuing without it", exc)
            return []
        return [(str(tid), str(name)) for tid, name in found]

    def _parent_name(self, technique_id: str) -> str:
        """The parent technique's name, or "" for a top-level or unresolvable ID.

        An in-process lookup, not a subprocess, so a second call per
        sub-technique costs nothing worth caching. A failure only costs the
        grounding audit one name to match on, so it is not worth raising.
        """
        if "." not in technique_id:
            return ""
        from hecate_agent.api import lookup_technique

        try:
            data = self._with_context(lookup_technique, technique_id=technique_id.split(".")[0])
        except RuntimeError:
            return ""
        return str(data.get("name", "")) if data.get("found") else ""

    def link_research_to_hunt(
        self, research_id: str, hunt_id: str, timeout_sec: int | None = None
    ) -> None:
        from hecate_agent.api import link_research_to_hunt

        self._with_context(
            link_research_to_hunt,
            research_id=research_id,
            hunt_id=hunt_id,
            workspace=self.workspace,
        )
