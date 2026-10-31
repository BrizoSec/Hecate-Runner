"""Reviewed, read-only procedures for unattended execution in the Linux lab.

Technique IDs alone are not an execution policy: CALDERA may map a technique
to downloads, payloads, or commands containing facts from intelligence. Pin the
ability and inspect its executable content before allowing it to run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hecate_runner.bas.base import SafetyViolationError


@dataclass(frozen=True)
class ApprovedProcedure:
    technique_id: str
    ability_id: str
    command: str


APPROVED_PROCEDURES = {
    "T1033": ApprovedProcedure("T1033", "bd527b63-9f9e-46e0-9816-b8434d2b8989", "whoami"),
    "T1057": ApprovedProcedure("T1057", "335cea7b-bec0-48c6-adfb-6066070f5f68", "ps"),
    "T1083": ApprovedProcedure("T1083", "52177cc1-b9ab-4411-ac21-2eadc4b5d3b8", "ls"),
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
                return APPROVED_PROCEDURES[technique], text
    return None
