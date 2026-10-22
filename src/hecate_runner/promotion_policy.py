"""Deterministic risk policy for planning-hunt publication and auto-merge."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from hecate_runner.hunt_audit import audit_hunt_text, parse_hunt_file, research_text_for

_HUNT_ID_RE = re.compile(r"^H-\d{4,}$")
_TLP_RE = re.compile(
    r"\bTLP\s*[:\-]\s*(AMBER(?:\+STRICT|\s+STRICT)?|RED|GREEN|CLEAR|WHITE)\b",
    re.IGNORECASE,
)
_ACTIONS = {"allow", "review", "block", "allow_private"}


@dataclass(frozen=True)
class PromotionDecision:
    hunt_id: str
    eligible: bool
    review_required: bool
    reasons: list[str]
    unsupported_claims: int
    tlp: str | None
    policy_version: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_frontmatter(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("hunt has no YAML frontmatter")
    try:
        end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration as exc:
        raise ValueError("hunt frontmatter is not closed") from exc
    try:
        value = yaml.safe_load("\n".join(lines[1:end]))
    except yaml.YAMLError as exc:
        raise ValueError("hunt frontmatter is not valid YAML") from exc
    if not isinstance(value, dict):
        raise ValueError("hunt frontmatter must be a mapping")
    return value


def load_policy(workspace: Path) -> dict[str, Any]:
    path = workspace / "promotion-policy.yaml"
    if not path.is_file():
        raise ValueError("promotion-policy.yaml is required")
    try:
        policy = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError("promotion policy is not valid YAML") from exc
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ValueError("unsupported promotion policy version")
    if policy.get("target_visibility") != "private":
        raise ValueError("automatic publication requires target_visibility: private")
    merge = policy.get("auto_merge")
    risks = policy.get("risk")
    review = policy.get("review")
    if not isinstance(merge, dict) or not isinstance(risks, dict) or not isinstance(review, dict):
        raise ValueError("policy must define auto_merge and risk mappings")
    if not isinstance(merge.get("enabled"), bool):
        raise ValueError("auto_merge.enabled must be a boolean")
    if merge.get("merge_method", "squash") not in {"merge", "squash", "rebase"}:
        raise ValueError("auto_merge.merge_method must be merge, squash, or rebase")
    minimum = review.get("minimum_approvals")
    associations = review.get("allowed_associations")
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 1:
        raise ValueError("review.minimum_approvals must be a positive integer")
    if (
        not isinstance(associations, list)
        or not associations
        or not all(value in {"OWNER", "MEMBER", "COLLABORATOR"} for value in associations)
    ):
        raise ValueError("review.allowed_associations must contain qualified GitHub roles")
    if not isinstance(policy.get("publisher_login"), str) or not policy["publisher_login"].endswith(
        "[bot]"
    ):
        raise ValueError("publisher_login must name the GitHub App bot account")
    for key in (
        "missing_cti",
        "missing_research",
        "missing_sigma",
        "incomplete_metadata",
        "low_confidence_source",
        "unsupported_claims",
        "tlp_amber",
        "unknown_tlp",
    ):
        if risks.get(key) not in _ACTIONS:
            raise ValueError(f"promotion policy has an invalid action for risk.{key}")
    return policy


def evaluate_promotion(workspace: Path, hunt_id: str) -> PromotionDecision:
    """Classify whether a planning hunt can pass the required policy check."""
    if not _HUNT_ID_RE.fullmatch(hunt_id):
        raise ValueError("hunt ID must look like H-0001")
    workspace = workspace.resolve()
    policy = load_policy(workspace)
    matches = sorted((workspace / "hunts").glob(f"**/{hunt_id}.md"))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one hunt file for {hunt_id}; found {len(matches)}")
    text = matches[0].read_text(encoding="utf-8")
    metadata = _load_frontmatter(text)
    if metadata.get("hunt_id") != hunt_id:
        raise ValueError("hunt frontmatter ID does not match its filename")
    if metadata.get("status") != "planning":
        raise ValueError("only status: planning bundles can be promoted")

    facts = parse_hunt_file(text)
    if facts.hunt_id != hunt_id:
        raise ValueError("hunt ID could not be recovered from frontmatter")
    research = research_text_for(workspace, facts.research_id)
    _, report = audit_hunt_text(text)
    unsupported = int(report.counts.get("unsupported", 0))

    reasons: list[str] = []
    review_required = False
    risk = policy["risk"]

    def apply(action: str, reason: str) -> None:
        nonlocal review_required
        if action == "block":
            raise ValueError(reason)
        if action == "review":
            review_required = True
            reasons.append(reason)
        elif action == "allow_private":
            # The publisher independently verifies that the destination is private.
            reasons.append(f"{reason} (private repository policy)")

    if not facts.has_cti:
        apply(str(risk["missing_cti"]), "source CTI is missing from the hunt")
    if facts.research_id and not (workspace / "research" / f"{facts.research_id}.md").is_file():
        apply(str(risk["missing_research"]), "linked research document is missing")
    query_dir = workspace / "queries" / hunt_id
    sigma_files = list(query_dir.glob("*.yml")) + list(query_dir.glob("*.yaml"))
    if not sigma_files:
        apply(str(risk["missing_sigma"]), "no Sigma rule was generated for this hunt")
    if (
        not metadata.get("techniques")
        or not metadata.get("platform")
        or not metadata.get("data_sources")
    ):
        apply(
            str(risk["incomplete_metadata"]),
            "hunt has incomplete technique, platform, or data-source metadata",
        )
    tags = metadata.get("tags") or []
    if not isinstance(tags, list):
        raise ValueError("hunt tags must be a list")
    if "low-confidence-source" in {str(tag).lower() for tag in tags}:
        apply(str(risk["low_confidence_source"]), "source is tagged low confidence")
    if unsupported:
        apply(
            str(risk["unsupported_claims"]),
            f"grounding audit found {unsupported} unsupported claim(s)",
        )

    matches_tlp = _TLP_RE.findall("\n".join((facts.cti_text, research)))
    tlp_values = [match.upper().replace("  ", " ") for match in matches_tlp]
    rank = {
        "CLEAR": 0,
        "WHITE": 0,
        "GREEN": 1,
        "AMBER": 2,
        "AMBER STRICT": 3,
        "AMBER+STRICT": 3,
        "RED": 4,
    }
    tlp = max(tlp_values, key=lambda value: rank.get(value, 0), default=None)
    if tlp == "RED":
        raise ValueError("TLP:RED material cannot be published to the content workspace")
    if tlp and tlp.startswith("AMBER"):
        apply(str(risk["tlp_amber"]), f"source carries {tlp}")
    elif tlp is None:
        apply(str(risk["unknown_tlp"]), "source has no explicit TLP marking")

    return PromotionDecision(
        hunt_id=hunt_id,
        eligible=bool(policy["auto_merge"].get("enabled", False)) and not review_required,
        review_required=review_required,
        reasons=reasons,
        unsupported_claims=unsupported,
        tlp=tlp,
        policy_version=int(policy["version"]),
    )
