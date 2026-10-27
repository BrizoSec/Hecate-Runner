"""Tests for Closed-Loop Detection Verifier."""

from datetime import UTC, datetime

from hecate_runner.bas.base import DetonationResult, DetonationStage
from hecate_runner.bas.verifier import (
    DetectionVerifier,
    VerificationResult,
    VerificationStatus,
)
from hecate_runner.query_execution import ProposedQuery, QueryProvider, QueryResult


class DynamicMockQueryProvider(QueryProvider):
    """Mock query provider with configurable row counts across polls."""

    name = "dynamic_mock"

    def __init__(self, responses: list[int] | None = None):
        self.responses = list(responses or [1])
        self.call_count = 0
        self.queries_executed: list[ProposedQuery] = []

    def execute(self, query: ProposedQuery) -> QueryResult:
        self.queries_executed.append(query)
        idx = min(self.call_count, len(self.responses) - 1)
        count = self.responses[idx]
        self.call_count += 1
        return QueryResult(
            outcome="executed",
            provider=self.name,
            row_count=count,
            detail=f"Found {count} events",
        )


def make_sample_detonation(
    success: bool = True,
    technique_id: str = "T1059.001",
    ability_id: str = "ability-psh-01",
    telemetry: list[dict] | None = None,
) -> DetonationResult:
    now = datetime.now(UTC)
    telemetry = (
        telemetry
        if telemetry is not None
        else [
            {
                "data_source": "process_creation",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc AAAAA...",
                "User": "SYSTEM",
            }
        ]
    )
    return DetonationResult(
        success=success,
        hunt_id="H-0885",
        technique_id=technique_id,
        ability_id=ability_id,
        provider="caldera",
        start_time_utc=now.isoformat(),
        end_time_utc=now.isoformat(),
        duration_seconds=5.0,
        exit_code=0 if success else 1,
        stdout="executed" if success else "",
        stderr="" if success else "detonation crashed",
        stage=DetonationStage.COMPLETED if success else DetonationStage.FAILED,
        telemetry_signatures=telemetry,
    )


SAMPLE_SIGMA_RULE = """
title: Suspicious Encoded PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""

NON_MATCHING_SIGMA_RULE = """
title: Suspicious Cmd Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
        CommandLine|contains: '/c whoami'
    condition: selection
"""


def test_verifier_detonation_failed():
    detonation = make_sample_detonation(success=False)
    verifier = DetectionVerifier()
    res = verifier.verify_detonation(detonation, rule_yaml=SAMPLE_SIGMA_RULE)
    assert res.status == VerificationStatus.DETONATION_FAILED
    assert res.rule_triggered is False
    assert res.telemetry_arrived is False


def test_verifier_time_window_calculation():
    verifier = DetectionVerifier(ingestion_slack_sec=45)
    start_utc = "2026-10-27T00:00:10Z"
    end_utc = "2026-10-27T00:00:20Z"
    start_dt, end_dt, start_str, end_str = verifier._calculate_time_window(start_utc, end_utc)

    # 10s backward skew
    assert start_dt.second == 0
    # 45s forward slack from end (20 + 45 = 65 -> 00:01:05)
    assert end_dt.second == 5
    assert end_dt.minute == 1
    assert "2026-10-27" in start_str
    assert "2026-10-27" in end_str


def test_verifier_true_positive_sigma_ast():
    detonation = make_sample_detonation()
    verifier = DetectionVerifier()
    res = verifier.verify_detonation(detonation, rule_yaml=SAMPLE_SIGMA_RULE)

    assert res.status == VerificationStatus.VERIFIED_TRUE_POSITIVE
    assert res.telemetry_arrived is True
    assert res.rule_triggered is True
    assert res.matched_events_count == 1
    assert "✓ TRUE POSITIVE" in res.summary()


def test_verifier_detection_miss_sigma_ast():
    # Telemetry is powershell, rule looks for cmd.exe
    detonation = make_sample_detonation()
    verifier = DetectionVerifier()
    res = verifier.verify_detonation(detonation, rule_yaml=NON_MATCHING_SIGMA_RULE)

    assert res.status == VerificationStatus.DETECTION_MISS
    assert res.telemetry_arrived is True
    assert res.rule_triggered is False
    assert res.matched_events_count == 0
    assert "✗ DETECTION MISS" in res.summary()


def test_verifier_telemetry_missing():
    # Empty telemetry
    detonation = make_sample_detonation(telemetry=[])
    verifier = DetectionVerifier()
    res = verifier.verify_detonation(detonation, rule_yaml=SAMPLE_SIGMA_RULE)

    assert res.status == VerificationStatus.TELEMETRY_MISSING
    assert res.telemetry_arrived is False
    assert res.rule_triggered is False
    assert "⚠ NO TELEMETRY" in res.summary()


def test_verifier_live_siem_polling_with_delay():
    # Simulate SIEM ingestion delay: 0 rows on 1st poll, 2 rows on 2nd poll
    provider = DynamicMockQueryProvider(responses=[0, 2])
    verifier = DetectionVerifier(
        query_provider=provider,
        poll_interval_sec=0.05,
        max_wait_sec=2.0,
    )
    detonation = make_sample_detonation(telemetry=[])
    res = verifier.verify_detonation(
        detonation,
        candidate_query="index=sysmon EventCode=1 powershell",
        backend="splunk",
    )

    assert res.status == VerificationStatus.VERIFIED_TRUE_POSITIVE
    assert res.rule_triggered is True
    assert res.matched_events_count == 2
    assert provider.call_count == 2


def test_verifier_serialization_round_trip():
    res = VerificationResult(
        hunt_id="H-0885",
        technique_id="T1059.001",
        ability_id="psh-cradle",
        provider="caldera",
        status=VerificationStatus.VERIFIED_TRUE_POSITIVE,
        telemetry_arrived=True,
        rule_triggered=True,
        detonation_start_utc="2026-10-27T00:00:00Z",
        detonation_end_utc="2026-10-27T00:00:10Z",
        window_start_utc="2026-10-26T23:59:50Z",
        window_end_utc="2026-10-27T00:00:40Z",
        matched_events_count=3,
        query_used="index=sysmon EventCode=1",
        backend="splunk",
        notes=["Matched 3 events"],
    )

    d = res.to_dict()
    assert d["status"] == "verified_true_positive"
    restored = VerificationResult.from_dict(d)
    assert restored.hunt_id == "H-0885"
    assert restored.status == VerificationStatus.VERIFIED_TRUE_POSITIVE
    assert restored.matched_events_count == 3
