"""Append-only per-cycle and per-stage runtime metrics."""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

log = logging.getLogger(__name__)


def _optional_int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _optional_float(value: Any) -> float | None:
    return float(value) if value is not None else None


@dataclass
class LLMUsage:
    """Provider usage reported by Core for one pipeline stage."""

    llm_calls: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    llm_duration_ms: int | None = None
    estimated_cost_usd: float | None = None
    models: list[str] = field(default_factory=list)

    @classmethod
    def from_metadata(cls, metadata: Mapping[str, Any]) -> LLMUsage:
        """Parse Core's additive usage fields, tolerating older Core versions."""
        models = metadata.get("models", metadata.get("llm_models", [])) or []
        if isinstance(models, str):
            models = [models]
        return cls(
            llm_calls=_optional_int(metadata.get("llm_calls")),
            input_tokens=_optional_int(metadata.get("input_tokens")),
            output_tokens=_optional_int(metadata.get("output_tokens")),
            llm_duration_ms=_optional_int(metadata.get("llm_duration_ms")),
            estimated_cost_usd=_optional_float(
                metadata.get("estimated_cost_usd", metadata.get("total_cost_usd"))
            ),
            models=[str(model) for model in models],
        )


@dataclass
class StageMetric:
    stage: str
    duration_ms: int
    status: str = "ok"
    llm_calls: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    llm_duration_ms: int | None = None
    estimated_cost_usd: float | None = None
    models: list[str] = field(default_factory=list)

    def apply_usage(self, usage: LLMUsage | None) -> None:
        if usage is None:
            return
        self.llm_calls = usage.llm_calls
        self.input_tokens = usage.input_tokens
        self.output_tokens = usage.output_tokens
        self.llm_duration_ms = usage.llm_duration_ms
        self.estimated_cost_usd = usage.estimated_cost_usd
        self.models = usage.models


class StageMeasurement:
    """Context manager that records wall latency even when a stage fails."""

    def __init__(self, owner: CycleMetrics, stage: str):
        self.owner = owner
        self.stage = stage
        self.started = time.monotonic()
        self.status = "ok"
        self.usage: LLMUsage | None = None

    def __enter__(self) -> StageMeasurement:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        if exc is not None:
            self.status = "error"
            if self.usage is None:
                self.usage = getattr(exc, "usage", None)
        self.owner._record(
            StageMetric(
                stage=self.stage,
                duration_ms=max(0, round((time.monotonic() - self.started) * 1000)),
                status=self.status,
                **(asdict(self.usage) if self.usage is not None else {}),
            )
        )
        return False

    def set_usage(self, usage: LLMUsage | None) -> None:
        self.usage = usage

    def set_status(self, status: str) -> None:
        self.status = status


class CycleMetrics:
    """Metrics accumulated for one Runner cycle."""

    def __init__(self, cycle_id: str):
        self.cycle_id = cycle_id
        self.started_at = datetime.now(UTC)
        self._started = time.monotonic()
        self.source = "unknown"
        self.source_id = ""
        self._stages: list[StageMetric] = []

    def measure(self, stage: str) -> StageMeasurement:
        return StageMeasurement(self, stage)

    def set_source(self, source: str, source_id: str = "") -> None:
        self.source = source or "unknown"
        self.source_id = source_id or ""

    def _record(self, metric: StageMetric) -> None:
        self._stages.append(metric)

    def to_record(
        self,
        *,
        outcome: str,
        hunt_id: str | None = None,
        research_id: str | None = None,
    ) -> dict[str, Any]:
        duration_ms = max(0, round((time.monotonic() - self._started) * 1000))
        stages = [asdict(metric) for metric in self._stages]
        stages.append(asdict(StageMetric(stage="cycle", duration_ms=duration_ms)))
        return {
            "schema_version": 1,
            "cycle_id": self.cycle_id,
            "started_at": self.started_at.isoformat(),
            "source": self.source,
            "source_id": self.source_id,
            "outcome": outcome,
            "hunt_id": hunt_id,
            "research_id": research_id,
            "duration_ms": duration_ms,
            "stages": stages,
        }


class MetricsStore:
    """Stores compact JSONL cycle records and aggregates them on demand."""

    def __init__(self, path: Path):
        self.path = path

    def append(self, record: Mapping[str, Any]) -> None:
        """Append one JSON object with a single O_APPEND write."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = (json.dumps(record, separators=(",", ":"), allow_nan=False) + "\n").encode()
        fd = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
        finally:
            os.close(fd)

    def aggregate(self, *, days: int = 30, source: str | None = None) -> list[dict[str, Any]]:
        """Summarize average stage latency and total LLM usage per source."""
        if not self.path.exists():
            return []

        cutoff = datetime.now(UTC) - timedelta(days=days)
        totals: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {
                "cycles": 0,
                "duration_ms": 0,
                "usage_samples": 0,
                "llm_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "llm_duration_ms": 0,
                "estimated_cost_usd": 0.0,
                "cost_samples": 0,
                "models": set(),
                "errors": 0,
            }
        )

        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            log.warning("Could not read stage metrics %s (%s)", self.path, exc)
            return []

        for line in lines:
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise TypeError("metrics record must be an object")
                timestamp = datetime.fromisoformat(record["started_at"])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                if timestamp < cutoff:
                    continue
                record_source = str(record.get("source") or "unknown")
                if source and record_source.lower() != source.lower():
                    continue

                # Coalesce repeated measurements of a stage within one cycle
                # (grounding can run before and after Sigma) so `cycles` and
                # average latency remain per-cycle statistics.
                cycle_stages: dict[str, dict[str, Any]] = {}
                stages = record.get("stages", [])
                if not isinstance(stages, list):
                    raise TypeError("metrics stages must be a list")
                for item in stages:
                    if not isinstance(item, dict):
                        raise TypeError("metrics stage must be an object")
                    name = str(item.get("stage") or "unknown")
                    combined = cycle_stages.setdefault(
                        name,
                        {
                            "duration_ms": 0,
                            "usage_known": False,
                            "llm_calls": 0,
                            "input_tokens": 0,
                            "output_tokens": 0,
                            "llm_duration_ms": 0,
                            "estimated_cost_usd": 0.0,
                            "cost_known": False,
                            "models": set(),
                            "errors": 0,
                        },
                    )
                    combined["duration_ms"] += int(item.get("duration_ms") or 0)
                    for field_name in ("llm_calls", "input_tokens", "output_tokens", "llm_duration_ms"):
                        value = item.get(field_name)
                        if value is not None:
                            combined[field_name] += int(value)
                            combined["usage_known"] = True
                    cost = item.get("estimated_cost_usd")
                    if cost is not None:
                        combined["estimated_cost_usd"] += float(cost)
                        combined["cost_known"] = True
                    combined["models"].update(item.get("models") or [])
                    combined["errors"] += int(item.get("status") in {"error", "partial"})

                for stage_name, stage in cycle_stages.items():
                    aggregate = totals[(stage_name, record_source)]
                    aggregate["cycles"] += 1
                    aggregate["duration_ms"] += stage["duration_ms"]
                    aggregate["usage_samples"] += int(stage["usage_known"])
                    for field_name in ("llm_calls", "input_tokens", "output_tokens", "llm_duration_ms"):
                        aggregate[field_name] += stage[field_name]
                    if stage["cost_known"]:
                        aggregate["estimated_cost_usd"] += stage["estimated_cost_usd"]
                        aggregate["cost_samples"] += 1
                    aggregate["models"].update(stage["models"])
                    aggregate["errors"] += stage["errors"]
            except (KeyError, TypeError, ValueError, AttributeError):
                log.warning("Skipping malformed stage metrics line in %s", self.path)

        rows = []
        for (stage_name, record_source), values in totals.items():
            count = values["cycles"]
            rows.append(
                {
                    "stage": stage_name,
                    "source": record_source,
                    "cycles": count,
                    "avg_duration_ms": round(values["duration_ms"] / count),
                    "total_duration_ms": values["duration_ms"],
                    "llm_calls": values["llm_calls"] if values["usage_samples"] else None,
                    "input_tokens": values["input_tokens"] if values["usage_samples"] else None,
                    "output_tokens": values["output_tokens"] if values["usage_samples"] else None,
                    "llm_duration_ms": values["llm_duration_ms"] if values["usage_samples"] else None,
                    "estimated_cost_usd": (
                        round(values["estimated_cost_usd"], 6)
                        if values["cost_samples"]
                        else None
                    ),
                    "cost_samples": values["cost_samples"],
                    "models": sorted(values["models"]),
                    "errors": values["errors"],
                }
            )
        return sorted(rows, key=lambda row: (row["source"], row["stage"]))
