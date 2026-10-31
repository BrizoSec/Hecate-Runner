"""Reviewed, read-only procedures for unattended execution in the Linux lab.

Technique IDs alone are not an execution policy: CALDERA may map a technique
to downloads, payloads, or commands containing facts from intelligence. Pin the
ability and inspect its executable content before allowing it to run.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from hecate_runner.bas.base import SafetyViolationError


@dataclass(frozen=True)
class ApprovedProcedure:
    technique_id: str
    ability_id: str
    command: str
    observed_argv: tuple[str, ...] = ()
    managed: bool = False

    @property
    def argv(self) -> tuple[str, ...]:
        return self.observed_argv or tuple(shlex.split(self.command))


def _managed(technique: str, command: str, observed: tuple[str, ...] = ()) -> ApprovedProcedure:
    identity = str(uuid5(NAMESPACE_URL, f"https://hecate.local/bas/{technique}/v1/{command}"))
    return ApprovedProcedure(technique, identity, command, observed, True)


APPROVED_PROCEDURES = {
    "T1033": ApprovedProcedure("T1033", "bd527b63-9f9e-46e0-9816-b8434d2b8989", "whoami"),
    "T1057": ApprovedProcedure("T1057", "335cea7b-bec0-48c6-adfb-6066070f5f68", "ps"),
    "T1083": ApprovedProcedure("T1083", "52177cc1-b9ab-4411-ac21-2eadc4b5d3b8", "ls"),
    "T1082": _managed("T1082", "uname -a"),
    "T1016": _managed("T1016", "ip address show"),
    "T1087.001": _managed("T1087.001", "cut -d: -f1 /etc/passwd"),
    "T1069.001": ApprovedProcedure("T1069.001", "5c4dd985-89e3-4590-9b57-71fed66ff4e2", "groups"),
    "T1124": _managed("T1124", 'date -u +"%Y-%m-%dT%H:%M:%SZ"'),
    "T1059.004": _managed("T1059.004", "sh -c 'printf hecate-bas-shell-probe'"),
    "T1140": _managed("T1140", "printf 'aGVjYXRlLWJhcy1wcm9iZQ==' | base64 -d", ("base64", "-d")),
}


def ability_definition(procedure: ApprovedProcedure) -> dict[str, Any]:
    """Exact fixed content for a Hecate-managed ability; no CTI inputs."""
    if APPROVED_PROCEDURES.get(procedure.technique_id) != procedure or not procedure.managed:
        raise SafetyViolationError("Only catalog-managed abilities can be installed.")
    return {
        "id": procedure.ability_id,
        "name": f"Hecate isolated lab {procedure.technique_id}",
        "description": "Pinned non-destructive Linux lab procedure; local sensor verification.",
        "tactic": {"T1059.004": "execution", "T1140": "stealth"}.get(
            procedure.technique_id, "discovery"
        ),
        "technique": {"attack_id": procedure.technique_id, "name": procedure.technique_id},
        "platforms": {"linux": {"sh": {"command": procedure.command, "timeout": 10}}},
    }


def validate_approved_ability(ability: dict[str, Any], procedure: ApprovedProcedure) -> None:
    """Reject altered commands and any additional executable behavior."""
    if (
        ability.get("ability_id") != procedure.ability_id
        or ability.get("technique_id") != procedure.technique_id
        or ability.get("requirements")
        or ability.get("privilege")
    ):
        raise SafetyViolationError("Approved CALDERA ability identity or requirements changed.")
    executors = [e for e in ability.get("executors", []) if e.get("platform") == "linux"]
    if len(executors) != 1:
        raise SafetyViolationError("Approved ability requires exactly one Linux executor.")
    executor = executors[0]
    if (
        executor.get("name") != "sh"
        or executor.get("command") != procedure.command
        or any(
            executor.get(key)
            for key in (
                "cleanup",
                "payloads",
                "uploads",
                "variations",
                "code",
                "build_target",
                "parsers",
                "additional_info",
            )
        )
    ):
        raise SafetyViolationError("Approved CALDERA procedure content changed; execution refused.")


def select_approved_rule(
    rules: list[dict[str, Any]], techniques: list[str], allowed: list[str]
) -> tuple[ApprovedProcedure, str] | None:
    """Select a matching Linux process rule, without broadening to parent techniques."""
    import yaml

    for rule in rules:
        text = rule.get("rule_yaml", "")
        try:
            parsed = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(parsed, dict):
            continue
        source = parsed.get("logsource") or {}
        if not isinstance(source, dict):
            continue
        if source.get("product") != "linux" or source.get("category") != "process_creation":
            continue
        tags = {str(t).lower() for t in parsed.get("tags") or []}
        rule_techniques = {str(t).upper() for t in rule.get("techniques") or []}
        rule_techniques.update(
            t.removeprefix("attack.").upper() for t in tags if t.startswith("attack.t")
        )
        for technique in techniques:
            if (
                technique in allowed
                and technique in rule_techniques
                and technique in APPROVED_PROCEDURES
            ):
                procedure = APPROVED_PROCEDURES[technique]
                # Eligibility only: a shared ATT&CK tag does not mean this
                # fixed procedure exercises the rule's actual predicates.
                # Validation still requires independently observed live events.
                from hecate_agent.core.sigma_evaluator import SigmaEvaluator

                candidates = [
                    {
                        "data_source": "process_creation",
                        "product": "linux",
                        "Image": f"{directory}/{procedure.argv[0]}",
                        "CommandLine": shlex.join(procedure.argv),
                    }
                    for directory in ("/bin", "/usr/bin", "/sbin", "/usr/sbin")
                ]
                try:
                    if SigmaEvaluator.evaluate_rule(text, candidates, []).true_positives > 0:
                        return procedure, text
                except Exception:
                    continue
    return None
