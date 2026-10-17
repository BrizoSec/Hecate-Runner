"""Python API client wrapping the hecate_agent package."""

from __future__ import annotations

import importlib.util
import inspect
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hecate_runner.metrics import LLMUsage

log = logging.getLogger(__name__)


#: Hecate's research writes this as skill 3's only finding when it judges the
#: source to describe no adversary behavior (``_NO_TELEMETRY_KEY_FINDING``).
_NO_BEHAVIOR_FINDING = "No telemetry mapped - the source describes no behavior"

#: How Hecate's Sigma API reports that every proposed rule was rejected
#: (``SigmaGeneratorAgent.execute``), with the reasons joined by "; ".
_NO_VALID_RULE_RE = re.compile(
    r"Sigma generation failed: no log source produced a valid rule: (.*)\Z", re.S
)


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
    usage: LLMUsage | None = None
    #: Web searches that succeeded, and why there were none when that is 0.
    web_searches: int = 0
    web_search_note: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.research_id.strip()

    @property
    def grounding(self) -> str:
        """``independent`` with at least one web search, else ``source-only``.

        Source-only research restates the item it was given, so it cannot
        corroborate that item and is not counted as evidence.
        """
        return "independent" if self.web_searches > 0 else "source-only"

    def grounding_label(self) -> str:
        if self.grounding == "independent":
            return f"independent research, {self.web_searches} web search(es)"
        note = f": {self.web_search_note}" if self.web_search_note else ""
        return f"source-only synthesis, 0 web searches{note}"


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
    indicator_records: list[dict[str, Any]] = field(default_factory=list)
    expected_malicious: str = ""
    expected_benign: str = ""
    falsification_criteria: str = ""
    rubric_score: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    raw_output: str = ""
    usage: LLMUsage | None = None
    fallback: bool = False

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
    def __init__(self, message: str, *, usage: LLMUsage | None = None):
        super().__init__(message)
        self.usage = usage


@dataclass
class SigmaResult:
    success: bool
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    logsources_considered: list[str] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    rules: list[dict[str, Any]] = field(default_factory=list)
    usage: LLMUsage | None = None
    #: Behaviours the rule reviewer found no rule for (each with a verified quote).
    review_gaps: list[dict[str, str]] = field(default_factory=list)


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
            metadata = getattr(exc, "metadata", {})
            usage = LLMUsage.from_metadata(metadata) if isinstance(metadata, dict) else None
            raise HecateError(f"Hecate API error: {exc}", usage=usage) from exc
        finally:
            os.chdir(original_cwd)
            os.environ.clear()
            os.environ.update(original_env)

    def source_evidence(self, url: str) -> Any:
        """Verified artifacts from the report at ``url`` (hecate_agent.core.source_evidence).

        In-process, under the workspace environment so the extraction uses the
        workspace's model. Never raises for a fetch or model failure; those
        come back on the result's ``error``.
        """
        from hecate_agent.core.source_evidence import extract_source_evidence

        return self._with_context(extract_source_evidence, url)

    def indicator_records(self, indicators: dict[str, list[str]], evidence: Any) -> list[Any]:
        """The feed's indicators typed by role and status against ``evidence``."""
        from hecate_agent.core.source_evidence import build_indicator_records

        return list(self._with_context(build_indicator_records, indicators, evidence))

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
            web_searches=int(getattr(output, "web_searches_performed", 0) or 0),
            web_search_note=str(getattr(output, "web_search_note", "") or ""),
            describes_behavior=not (
                telemetry_findings
                and all(f.startswith(_NO_BEHAVIOR_FINDING) for f in telemetry_findings)
            ),
            usage=LLMUsage(
                llm_calls=getattr(output, "llm_calls", None),
                input_tokens=getattr(output, "input_tokens", None),
                output_tokens=getattr(output, "output_tokens", None),
                llm_duration_ms=getattr(output, "llm_duration_ms", None),
                estimated_cost_usd=getattr(output, "total_cost_usd", None),
                models=list(getattr(output, "llm_models", []) or []),
            ),
        )

    def hypothesis_generator(
        self,
        threat_intel: str,
        research_id: str | None = None,
        timeout_sec: int | None = None,
        indicators_only: bool = False,
    ) -> HypothesisResult:
        from hecate_agent import api

        generate_with_metrics = getattr(api, "generate_hypothesis_with_metrics", None)
        kwargs = {
            "threat_intel": threat_intel,
            "research_id": research_id,
            "indicators_only": indicators_only,
            "workspace": self.workspace,
        }
        if generate_with_metrics is not None:
            output, metadata = self._with_context(generate_with_metrics, **kwargs)
            usage = LLMUsage.from_metadata(metadata)
            fallback = bool(metadata.get("fallback", False))
        else:  # older Core releases still get wall latency from the Runner
            output = self._with_context(api.generate_hypothesis, **kwargs)
            usage = None
            fallback = False
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
            indicator_records=getattr(output, "indicator_records", []),
            expected_malicious=getattr(output, "expected_malicious", "") or "",
            expected_benign=getattr(output, "expected_benign", "") or "",
            falsification_criteria=getattr(output, "falsification_criteria", "") or "",
            rubric_score=getattr(output, "rubric_score", {}) or {},
            warnings=[],
            raw_output="",
            usage=usage,
            fallback=fallback,
        )

    def sigma_generator(
        self,
        payload: dict[str, Any],
        out_dir: Path,
        timeout_sec: int | None = None,
    ) -> SigmaResult:
        from hecate_agent import api

        generate_with_metrics = getattr(api, "generate_sigma_with_metrics", None)
        if generate_with_metrics is not None:
            output, files, metadata = self._with_context(
                generate_with_metrics,
                payload=payload,
                out_dir=out_dir,
                hunt_id=payload.get("hunt_id"),
            )
            usage = LLMUsage.from_metadata(metadata)
            rules = [
                {
                    "logsource_category": rule.logsource_category,
                    "title": rule.title,
                    "level": rule.level,
                    "techniques": rule.techniques,
                    "rule_yaml": rule.rule_yaml,
                }
                for rule in output.rules
            ]
            return SigmaResult(
                success=bool(metadata.get("success", False)),
                error=metadata.get("error"),
                warnings=list(metadata.get("warnings") or []),
                logsources_considered=output.logsources_considered,
                rejected=output.rejected,
                files=files,
                rules=rules,
                usage=usage,
                review_gaps=list(getattr(output, "review_gaps", []) or []),
            )

        def generate() -> Any:
            try:
                return api.generate_sigma(
                    payload=payload, out_dir=out_dir, hunt_id=payload.get("hunt_id")
                )
            except RuntimeError as exc:
                # Every proposed rule failed validation: an outcome, not a
                # fault. Raised, it reached `_with_context` and was logged as
                # an ERROR with a traceback on a cycle that then created its
                # draft normally -- and the rejection reasons were lost.
                reasons = _NO_VALID_RULE_RE.match(str(exc))
                if reasons is None:
                    raise
                return SigmaResult(
                    success=False,
                    error="no log source produced a valid rule",
                    warnings=[],
                    rejected=[r for r in reasons.group(1).split("; ") if r],
                )

        generated = self._with_context(generate)
        if isinstance(generated, SigmaResult):
            return generated
        output, files = generated
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
