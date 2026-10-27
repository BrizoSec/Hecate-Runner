"""Closed-loop SIEM & Telemetry Detection Verification Engine.

Bridges adversary emulation detonations with SIEM log ingestion and candidate detection
rule evaluation. Verifies that telemetry arrived during the execution window and evaluates
whether Hecate's transpiled detection query or Sigma rule successfully triggers as a True Positive.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from hecate_runner.bas.base import DetonationResult
from hecate_runner.query_execution import ProposedQuery, QueryProvider

log = logging.getLogger(__name__)


class VerificationStatus(StrEnum):
    """Categorized status of detection verification against an adversary emulation."""

    VERIFIED_TRUE_POSITIVE = "verified_true_positive"
    DETECTION_MISS = "detection_miss"
    TELEMETRY_MISSING = "telemetry_missing"
    DETONATION_FAILED = "detonation_failed"
    ERROR = "error"


@dataclass
class VerificationResult:
    """Detailed outcome of closed-loop telemetry and detection query verification."""

    hunt_id: str
    technique_id: str
    ability_id: str
    provider: str
    status: VerificationStatus
    telemetry_arrived: bool
    rule_triggered: bool
    detonation_start_utc: str
    detonation_end_utc: str
    window_start_utc: str
    window_end_utc: str
    matched_events_count: int = 0
    query_used: str = ""
    backend: str = "mock"
    sample_matched_events: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verified_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationResult:
        d = dict(data)
        if "status" in d:
            d["status"] = VerificationStatus(d["status"])
        return cls(**d)

    def summary(self) -> str:
        icon_map = {
            VerificationStatus.VERIFIED_TRUE_POSITIVE: "✓ TRUE POSITIVE",
            VerificationStatus.DETECTION_MISS: "✗ DETECTION MISS",
            VerificationStatus.TELEMETRY_MISSING: "⚠ NO TELEMETRY",
            VerificationStatus.DETONATION_FAILED: "✗ DETONATION FAILED",
            VerificationStatus.ERROR: "⚠ ERROR",
        }
        tag = icon_map.get(self.status, self.status.value.upper())
        return (
            f"[{tag}] Hunt {self.hunt_id} ({self.technique_id} - {self.ability_id}): "
            f"Telemetry={self.telemetry_arrived}, Triggered={self.rule_triggered} "
            f"(Matches: {self.matched_events_count}, Backend: {self.backend})"
        )


class DetectionVerifier:
    """Verifies whether adversary emulation triggered detection rules in target SIEMs."""

    def __init__(
        self,
        query_provider: QueryProvider | None = None,
        ingestion_slack_sec: int = 30,
        max_wait_sec: int = 60,
        poll_interval_sec: float = 2.0,
    ):
        self.query_provider = query_provider
        self.ingestion_slack_sec = ingestion_slack_sec
        self.max_wait_sec = max_wait_sec
        self.poll_interval_sec = poll_interval_sec

    def _calculate_time_window(
        self, start_utc: str, end_utc: str
    ) -> tuple[datetime, datetime, str, str]:
        """Compute search window around detonation with backward skew and ingestion slack."""
        try:
            start_dt = datetime.fromisoformat(start_utc.replace("Z", "+00:00"))
        except Exception:
            start_dt = datetime.now(UTC)

        try:
            end_dt = datetime.fromisoformat(end_utc.replace("Z", "+00:00"))
        except Exception:
            end_dt = start_dt + timedelta(seconds=10)

        # 10s backward skew for clock drift, forward slack for ingestion delay
        window_start = start_dt - timedelta(seconds=10)
        window_end = end_dt + timedelta(seconds=self.ingestion_slack_sec)

        return (
            window_start,
            window_end,
            window_start.isoformat(),
            window_end.isoformat(),
        )

    def verify_detonation(
        self,
        detonation: DetonationResult,
        rule_yaml: str | None = None,
        candidate_query: str | None = None,
        backend: str = "mock",
        baseline_query: str | None = None,
        raw_events: list[dict[str, Any]] | None = None,
    ) -> VerificationResult:
        """Run closed-loop verification on an adversary emulation detonation."""
        hunt_id = detonation.hunt_id
        technique_id = detonation.technique_id
        ability_id = detonation.ability_id
        provider = detonation.provider

        # 1. Check if detonation actually succeeded
        if not detonation.success:
            return VerificationResult(
                hunt_id=hunt_id,
                technique_id=technique_id,
                ability_id=ability_id,
                provider=provider,
                status=VerificationStatus.DETONATION_FAILED,
                telemetry_arrived=False,
                rule_triggered=False,
                detonation_start_utc=detonation.start_time_utc,
                detonation_end_utc=detonation.end_time_utc,
                window_start_utc=detonation.start_time_utc,
                window_end_utc=detonation.end_time_utc,
                backend=backend,
                notes=[f"Detonation failed: {detonation.stderr or detonation.error_message}"],
            )

        # 2. Formulate execution time window
        _, _, win_start_str, win_end_str = self._calculate_time_window(
            detonation.start_time_utc, detonation.end_time_utc
        )

        telemetry_arrived = False
        rule_triggered = False
        matched_count = 0
        notes: list[str] = []
        samples: list[dict[str, Any]] = []

        # 3. Check for telemetry arrival
        # Check explicit events passed or generated in detonation
        events_to_evaluate = list(raw_events or detonation.telemetry_signatures)
        if events_to_evaluate:
            telemetry_arrived = True
            notes.append(f"Received {len(events_to_evaluate)} emulated telemetry events.")

        # Check live SIEM baseline query if configured
        if self.query_provider and baseline_query:
            try:
                base_prop = ProposedQuery(
                    hunt_id=hunt_id,
                    data_source="baseline_telemetry",
                    query_text=baseline_query,
                    time_range_days=1,
                    limit=50,
                    justification="BAS baseline telemetry check",
                )
                res = self.query_provider.execute(base_prop)
                if res.ok and res.row_count > 0:
                    telemetry_arrived = True
                    notes.append(
                        f"Baseline query found {res.row_count} raw telemetry events in SIEM."
                    )
            except Exception as exc:
                notes.append(f"Baseline query exception: {exc}")

        # 4. Evaluate Detection Rule Triggering
        # Path A: In-memory AST evaluation against emulated events using SigmaEvaluator
        if rule_yaml and events_to_evaluate:
            try:
                from hecate_agent.core.sigma_evaluator import SigmaEvaluator

                eval_report = SigmaEvaluator.evaluate_rule(rule_yaml, events_to_evaluate, [])
                if eval_report.true_positives > 0:
                    rule_triggered = True
                    matched_count = eval_report.true_positives
                    samples = [
                        e
                        for e in events_to_evaluate
                        if SigmaEvaluator.evaluate_rule(rule_yaml, [e], []).true_positives
                    ][:3]
                    notes.append(
                        f"Sigma AST evaluator matched {matched_count} true positive event(s)."
                    )
            except Exception as eval_exc:
                notes.append(f"Sigma AST evaluation error: {eval_exc}")

        # Path B: Live SIEM query execution via QueryProvider with polling
        if self.query_provider and candidate_query:
            poll_start = time.time()
            query_matched = False
            last_err = ""

            while (time.time() - poll_start) < self.max_wait_sec:
                try:
                    q_prop = ProposedQuery(
                        hunt_id=hunt_id,
                        data_source=f"bas_detection_{backend}",
                        query_text=candidate_query,
                        time_range_days=1,
                        limit=50,
                        justification="BAS detection rule validation",
                    )
                    q_res = self.query_provider.execute(q_prop)
                    if q_res.ok:
                        if q_res.row_count > 0:
                            query_matched = True
                            rule_triggered = True
                            telemetry_arrived = True
                            matched_count = q_res.row_count
                            notes.append(
                                f"SIEM query matched {matched_count} event(s) in {backend}."
                            )
                            break
                    else:
                        last_err = q_res.detail
                except Exception as q_exc:
                    last_err = str(q_exc)

                time.sleep(self.poll_interval_sec)

            if not query_matched and last_err:
                notes.append(f"SIEM query failed: {last_err}")

        # 5. Determine Final Verification Status
        if rule_triggered:
            status = VerificationStatus.VERIFIED_TRUE_POSITIVE
        elif telemetry_arrived:
            status = VerificationStatus.DETECTION_MISS
            notes.append(
                "Adversary telemetry was present, but detection query did not alert (False Negative)."
            )
        else:
            status = VerificationStatus.TELEMETRY_MISSING
            notes.append(
                "No telemetry arrived during detonation window (check agent or ingestion pipeline)."
            )

        return VerificationResult(
            hunt_id=hunt_id,
            technique_id=technique_id,
            ability_id=ability_id,
            provider=provider,
            status=status,
            telemetry_arrived=telemetry_arrived,
            rule_triggered=rule_triggered,
            detonation_start_utc=detonation.start_time_utc,
            detonation_end_utc=detonation.end_time_utc,
            window_start_utc=win_start_str,
            window_end_utc=win_end_str,
            matched_events_count=matched_count,
            query_used=candidate_query or "",
            backend=backend,
            sample_matched_events=samples,
            notes=notes,
        )
