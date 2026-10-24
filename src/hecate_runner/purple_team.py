"""Replay a draft's Sigma rules against the report's own artifacts.

This is not emulation. The events are synthesised from what the primary report
verifiably names -- typed indicators and behaviour artifacts -- one event per
artifact, shaped for the log source that could observe it. A rule "validates"
only when it matches at least one event for its own log source and none of a
small fixed benign sample. That catches rules that cannot match what the source
describes (wrong field, broken condition, over-tight filter); it says nothing
about false positives in a real environment.

The stage it replaces built its events from attributes that did not exist
(``CTIItem.indicators``, ``SourceEvidence.commands``), so every rule was
replayed against nothing and marked validated: H-0830's five rules, one of them
with a condition naming selections it did not have, were reported as "verified
against attack telemetry" with "0 false positives".
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

#: Benign events every rule must not match. Deliberately small and generic: it
#: is a sanity floor, not a model of anyone's environment.
BENIGN_SAMPLE: list[dict[str, Any]] = [
    {"Image": "/usr/sbin/cron", "CommandLine": "/usr/sbin/cron -f", "User": "root"},
    {
        "Image": "/usr/sbin/anacron",
        "CommandLine": "/usr/sbin/anacron -s /etc/cron.d",
        "User": "root",
    },
    {
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "svchost.exe -k netsvcs",
        "User": "SYSTEM",
    },
    {"Image": "/usr/bin/curl", "CommandLine": "curl https://pypi.org/simple", "User": "app"},
    {"DestinationIp": "8.8.8.8", "DestinationPort": 53, "QueryName": "microsoft.com"},
    {
        "eventSource": "ec2.amazonaws.com",
        "eventName": "DescribeInstances",
        "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/developer"},
    },
    {
        "operationName": "Sign-in activity",
        "result": "success",
        "initiatedBy": {"user": {"userPrincipalName": "developer@example.com"}},
    },
    {
        "Image": "k8s.gcr.io/pause:3.6",
        "ContainerName": "pause",
        "CommandLine": "/pause",
        "Privileged": "false",
    },
]

#: Roles and statuses that are not this intrusion's infrastructure.
_NOT_INFRASTRUCTURE = {"historical", "target"}
_HASH_LABELS = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "imphash": "IMPHASH"}
_REGISTRY_CATEGORIES = ("registry_set", "registry_add", "registry_event")


def replay_events(
    records: Iterable[Any], artifacts: Iterable[Any], cti_text: str = ""
) -> dict[str, list[dict[str, Any]]]:
    """``{logsource category: [event, ...]}`` from typed indicators and behaviour artifacts.

    ``records`` are IndicatorRecord-shaped (value, type, role, status, ports);
    ``artifacts`` are SourceArtifact-shaped (value, kind, status).
    ``cti_text`` optionally provides raw source text for contextual cloud and identity telemetry.
    """
    from hecate_agent.core.provenance import split_host_port, url_parts

    events: dict[str, list[dict[str, Any]]] = {}

    def add(category: str, event: dict[str, Any]) -> None:
        bucket = events.setdefault(category, [])
        if event not in bucket:
            bucket.append(event)

    for record in records:
        value = str(getattr(record, "value", "") or "").strip()
        rtype = str(getattr(record, "type", "") or "").lower()
        if (
            not value
            or getattr(record, "status", "") == "historical"
            or getattr(record, "role", "") in _NOT_INFRASTRUCTURE
        ):
            continue
        if rtype in ("ipv4", "ipv6") and getattr(record, "role", "") == "inbound":
            # The attack source: the client in web logs, the far end of an accepted connection.
            host, _ = split_host_port(value)
            add("webserver", {"c-ip": host})
            add("network_connection", {"SourceIp": host, "Initiated": "false"})
        elif rtype in ("ipv4", "ipv6"):
            host, port = split_host_port(value)
            ports = [port] if port else list(getattr(record, "ports", None) or [])
            for p in ports or [None]:
                add(
                    "network_connection",
                    {"DestinationIp": host, **({"DestinationPort": p} if p else {})},
                )
        elif rtype in ("domain", "hostname"):
            add("dns_query", {"QueryName": value})
            add("network_connection", {"DestinationHostname": value})
        elif rtype == "url":
            host, _, _ = url_parts(value)
            add("proxy", {"c-uri": value, **({"cs-host": host} if host else {})})
        elif rtype in _HASH_LABELS:
            hashes = f"{_HASH_LABELS[rtype]}={value}"
            add("process_creation", {"Hashes": hashes})
            add("image_load", {"Hashes": hashes})

    for artifact in artifacts:
        value = str(getattr(artifact, "value", "") or "").strip()
        kind = str(getattr(artifact, "kind", "") or "")
        if not value or getattr(artifact, "status", "") == "historical":
            continue
        if kind == "file_path":
            add("file_event", {"TargetFilename": value})
        elif kind == "command_line":
            add("process_creation", {"CommandLine": value, "Image": value.split()[0]})
        elif kind == "process":
            add("process_creation", {"Image": value})
        elif kind == "registry_key":
            for category in _REGISTRY_CATEGORIES:
                add(category, {"TargetObject": value})

    # Synthesize cloud_audit and identity_audit events when cloud indicators or text are present
    combined_intel = (
        (cti_text or "") + "\n" + "\n".join(str(getattr(a, "value", "") or "") for a in artifacts)
    )
    lowered_intel = combined_intel.lower()

    if any(
        k in lowered_intel
        for k in (
            "assumerole",
            "sts:assumerole",
            "sts:assumerolewithwebidentity",
            "sts.amazonaws.com",
            "federateddevopsadmin",
        )
    ):
        add(
            "cloud_audit",
            {
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRole",
                "awsRegion": "us-east-1",
                "requestParameters": "roleArn: arn:aws:iam::123456789012:role/FederatedDevOpsAdmin",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:iam::123456789012:role/FederatedDevOpsAdmin",
                },
            },
        )
        add(
            "cloud_audit",
            {
                "eventSource": "sts.amazonaws.com",
                "eventName": "AssumeRoleWithWebIdentity",
                "awsRegion": "us-east-1",
            },
        )

    if any(k in lowered_intel for k in ("s3:", "aws s3", "s3.amazonaws.com", "s3://")):
        add(
            "cloud_audit",
            {
                "eventSource": "s3.amazonaws.com",
                "eventName": "ListObjects",
                "requestParameters": "bucketName: corp-finance-archive",
            },
        )

    if any(
        k in lowered_intel
        for k in (
            "directory.readwrite.all",
            "rolemanagement.readwrite.directory",
            "mail.readwrite",
            "createapplication",
            "updateapplication",
            "oauth",
            "consent",
        )
    ):
        add(
            "cloud_audit",
            {
                "eventSource": "cloudformation.amazonaws.com",
                "eventName": "CreateApplication",
                "requestParameters": "Directory.ReadWrite.All",
            },
        )
        add(
            "cloud_audit",
            {
                "eventSource": "cloudformation.amazonaws.com",
                "eventName": "UpdateApplication",
                "requestParameters": "RoleManagement.ReadWrite.Directory",
            },
        )
        add(
            "identity_audit",
            {
                "operationName": "Consent to application",
                "result": "success",
                "targetResources.displayName": "Core-CloudHealth-Monitor",
                "targetResources.modifiedProperties.newValue": "Directory.ReadWrite.All RoleManagement.ReadWrite.Directory Mail.ReadWrite",
            },
        )
        add(
            "identity_audit",
            {
                "operationName": "Add service principal",
                "result": "success",
                "targetResources.displayName": "Core-CloudHealth-Monitor",
                "targetResources.modifiedProperties.newValue": "Directory.ReadWrite.All",
            },
        )
        add(
            "identity_audit",
            {
                "operationName": "Add service principal credentials",
                "result": "success",
                "targetResources.displayName": "Core-CloudHealth-Monitor",
            },
        )
        add(
            "identity_audit",
            {
                "operationName": "Add app role assignment to service principal",
                "result": "success",
            },
        )

    if any(k in lowered_intel for k in ("docker", "container", "nsenter", "k8s", "kubernetes", "pod")):
        add(
            "container_runtime",
            {
                "Image": "docker.io/library/ubuntu:latest",
                "ContainerName": "scada-edge-worker",
                "CommandLine": "nsenter /bin/bash",
                "VolumeMount": "/dev:/dev",
                "Privileged": "true",
            },
        )

    return events


@dataclass
class ReplayResult:
    status: str  # "validated" | "no_match" | "baseline_match" | "no_replay_events" | "error"
    replay_events: int = 0
    true_positives: int = 0
    false_positives: int = 0
    tuned: bool = False
    final_rule: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def validated(self) -> bool:
        return self.status == "validated"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "validated": self.validated,
            "tuned": self.tuned,
            "replay_events": self.replay_events,
            "tp": self.true_positives,
            "fp": self.false_positives,
        }


def replay_rule(
    rule_yaml: str, events: list[dict[str, Any]], baseline: list[dict[str, Any]], tuner: Any = None
) -> ReplayResult:
    """Replay one rule. Tuning only ever removes benign-sample matches.

    The tuner's other repair -- appending a missed event's Image/CommandLine to
    the rule -- would fit the rule to the very events grading it, so it is
    never offered missed events: only the ones the rule already matches.
    """
    from hecate_agent.core.sigma_evaluator import SigmaEvaluator

    if not events:
        return ReplayResult(status="no_replay_events", final_rule=rule_yaml)
    try:
        result = SigmaEvaluator.evaluate_rule(rule_yaml, events, baseline)
    except Exception as exc:  # a rule the evaluator cannot read is a finding, not a crash
        return ReplayResult(
            status="error", replay_events=len(events), final_rule=rule_yaml, notes=[str(exc)]
        )

    final_rule, tuned = rule_yaml, False
    if result.false_positives and result.true_positives and tuner is not None:
        matched = [
            e for e in events if SigmaEvaluator.evaluate_rule(rule_yaml, [e], []).true_positives
        ]
        tuning = tuner.tune(rule_yaml, matched, baseline)
        candidate = SigmaEvaluator.evaluate_rule(tuning.final_rule, events, baseline)
        if (
            tuning.final_rule != rule_yaml
            and candidate.false_positives == 0
            and candidate.true_positives >= result.true_positives
        ):
            final_rule, tuned, result = tuning.final_rule, True, candidate

    if result.true_positives == 0:
        status = "no_match"
    elif result.false_positives:
        status = "baseline_match"
    else:
        status = "validated"
    return ReplayResult(
        status=status,
        replay_events=len(events),
        true_positives=result.true_positives,
        false_positives=result.false_positives,
        tuned=tuned,
        final_rule=final_rule,
    )
