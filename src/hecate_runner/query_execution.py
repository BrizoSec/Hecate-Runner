"""Bounded query proposal + execution -- the "propose, don't run" bridge.

Mirrors the CTIProvider/AthfClient pattern already used for CTI intake and
hypothesis generation: a small typed interface plus pluggable backends.

Deliberately narrow in scope: no LLM drafts or approves a query here. A
human proposes a query for a specific hunt; deterministic guardrails reject
anything unbounded before it's ever staged; a human explicitly approves
execution via its own command. Auto-drafting queries is a separate, higher-
stakes capability this module does not attempt.
"""

from __future__ import annotations

import json
import logging
import subprocess
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ProposedQuery:
    """A query staged for human approval before it touches a real data source."""

    hunt_id: str
    data_source: str
    query_text: str
    time_range_days: int
    limit: int
    justification: str = ""
    proposed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProposedQuery:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class QueryResult:
    """Outcome of actually executing a (guardrail-passed) proposed query."""

    outcome: str  # "executed" | "error"
    provider: str
    row_count: int = 0
    detail: str = ""
    executed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def ok(self) -> bool:
        return self.outcome == "executed"


def validate_guardrails(
    query: ProposedQuery,
    *,
    max_time_range_days: int = 7,
    max_limit: int = 1000,
) -> list[str]:
    """Return guardrail violations for a proposed query. Empty list == passes.

    Mirrors AGENTS.md's "Query Guardrails" section: bounded time range,
    bounded result count, non-empty query and data source. Deterministic and
    LLM-independent by design -- these are hard limits an operator sets, not
    suggestions a model (or a human in a hurry) can talk their way around.
    """
    violations: list[str] = []

    if not query.query_text.strip():
        violations.append("query_text is empty")

    if query.time_range_days <= 0:
        violations.append("time_range_days must be positive")
    elif query.time_range_days > max_time_range_days:
        violations.append(
            f"time_range_days={query.time_range_days} exceeds max_time_range_days="
            f"{max_time_range_days} (exploratory queries are capped at 7 days by default)"
        )

    if query.limit <= 0:
        violations.append("limit must be positive")
    elif query.limit > max_limit:
        violations.append(f"limit={query.limit} exceeds max_limit={max_limit}")

    if not query.data_source.strip():
        violations.append("data_source is required")

    return violations


class QueryProvider(ABC):
    """Executes a guardrail-passed query against a real or fake backend."""

    name: str

    @abstractmethod
    def execute(self, query: ProposedQuery) -> QueryResult: ...


class MockQueryProvider(QueryProvider):
    """Never touches a real system.

    Stands in until a live data source exists. Every result is clearly
    labeled as a mock so it can't be mistaken for a real query outcome.
    """

    name = "mock"

    def execute(self, query: ProposedQuery) -> QueryResult:
        log.info("[mock] Would execute on %s: %s", query.data_source, query.query_text)
        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=0,
            detail=(
                "Mock provider -- no real backend configured. Set "
                "SEC7669_QUERY_PROVIDER=splunk once real Splunk access exists."
            ),
        )


class SplunkQueryProvider(QueryProvider):
    """Shells out to `athf splunk search`, same subprocess pattern as AthfClient.

    Unvalidated against a real Splunk instance as of this writing -- there is
    no live Splunk access in this environment yet. The guardrail enforcement
    and propose/approve flow around this class are what's actually tested;
    this exists so wiring in real access later is a config change
    (SEC7669_QUERY_PROVIDER=splunk), not new code.
    """

    name = "splunk"

    def __init__(self, athf_bin: Path, workspace: Path, timeout_sec: int = 300):
        self.athf_bin = athf_bin
        self.workspace = workspace
        self.timeout_sec = timeout_sec

    def execute(self, query: ProposedQuery) -> QueryResult:
        cmd = [
            str(self.athf_bin),
            "splunk",
            "search",
            query.query_text,
            "--earliest",
            f"-{query.time_range_days}d",
            "--latest",
            "now",
            "--count",
            str(query.limit),
            "--format",
            "json",
        ]
        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.workspace),
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return QueryResult(
                outcome="error", provider=self.name, detail=f"timed out after {self.timeout_sec}s"
            )
        except FileNotFoundError:
            return QueryResult(outcome="error", provider=self.name, detail=f"athf binary missing at {self.athf_bin}")

        if result.returncode != 0:
            return QueryResult(outcome="error", provider=self.name, detail=result.stderr.strip()[:500])

        # `athf splunk search --format json` prints a human-readable banner to
        # stdout before the JSON array, even in JSON mode -- find where the
        # array starts rather than assuming the whole stream is valid JSON.
        start = result.stdout.find("[")
        if start == -1:
            return QueryResult(outcome="error", provider=self.name, detail="no JSON array in athf splunk output")

        try:
            data = json.loads(result.stdout[start:])
        except json.JSONDecodeError as exc:
            return QueryResult(outcome="error", provider=self.name, detail=f"could not parse results: {exc}")

        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=len(data),
            detail=result.stdout[start : start + 2000],
        )


def get_provider(name: str, *, athf_bin: Path | None = None, workspace: Path | None = None) -> QueryProvider:
    if name == "mock":
        return MockQueryProvider()
    if name == "splunk":
        if athf_bin is None or workspace is None:
            raise ValueError("splunk provider requires athf_bin and workspace")
        return SplunkQueryProvider(athf_bin=athf_bin, workspace=workspace)
    raise ValueError(f"Unknown query provider: {name!r}. Supported: mock, splunk")
