"""Verify model-supplied evidence references against the current CTI sources."""

from __future__ import annotations

import re
from typing import Any


def _normalized(text: str) -> str:
    """Normalize whitespace and case while preserving the words and punctuation."""
    return re.sub(r"\s+", " ", str(text or "")).strip().casefold()


def verify_claim_citations(
    hypothesis: Any,
    citations: list[dict[str, Any]] | None,
    feed_text: str,
    primary_source_text: str = "",
    source_url: str = "",
    source_name: str = "CTI feed",
) -> list[dict[str, str]]:
    """Return one auditable row per key claim, checking quotes and claim links.

    This verifies that a claimed source passage occurs in the provided CTI
    text and that the model's claim excerpt occurs in the named output field.
    It does not decide whether the passage semantically proves the claim; that
    distinction is stated in the rendered hunt.
    """
    claims: list[tuple[str, str]] = []
    for field in (
        "hypothesis",
        "justification",
        "actor",
        "behavior",
        "location",
        "evidence",
    ):
        value = str(getattr(hypothesis, field, "") or "").strip()
        if value:
            claims.append((field, value))
    claims.extend(
        ("techniques", str(value).strip())
        for value in getattr(hypothesis, "techniques", []) or []
        if str(value).strip()
    )
    claims.extend(
        ("observables", str(value).strip())
        for value in getattr(hypothesis, "observables", []) or []
        if str(value).strip()
    )

    feed = _normalized(feed_text)
    primary = _normalized(primary_source_text)
    citation_rows: list[dict[str, str]] = []
    normalized_citations: list[dict[str, str]] = []
    aliases = {
        "mitre_techniques": "techniques",
        "expected_observables": "observables",
    }
    for raw in citations or []:
        if not isinstance(raw, dict):
            continue
        field = aliases.get(
            str(raw.get("field", "")).strip().lower(), str(raw.get("field", "")).strip().lower()
        )
        claim = str(raw.get("claim") or "").strip()
        quote = str(raw.get("quote") or "").strip()
        normalized_citations.append({"field": field, "claim": claim, "quote": quote})

    for field, actual_claim in claims:
        actual = _normalized(actual_claim)
        field_citations = [c for c in normalized_citations if c["field"] == field]
        if not field_citations:
            citation_rows.append(
                {
                    "field": field,
                    "claim": actual_claim,
                    "quote": "",
                    "source": source_url or source_name,
                    "status": "no exact claim citation supplied",
                }
            )
            continue

        for citation in field_citations:
            if not citation["claim"] or _normalized(citation["claim"]) not in actual:
                citation_rows.append(
                    {
                        "field": field,
                        "claim": citation["claim"] or actual_claim,
                        "quote": citation["quote"],
                        "source": source_url or source_name,
                        "status": "claim excerpt does not match final field",
                    }
                )
                continue

            quote = citation["quote"]
            if not quote:
                status = "no quote supplied"
                source = source_name
            elif _normalized(quote) in primary:
                status = (
                    "source inventory verified; sweep is deterministic"
                    if getattr(hypothesis, "is_indicator_only", False)
                    else "quote found; relevance needs review"
                )
                source = source_url or "linked primary source"
            elif _normalized(quote) in feed:
                status = (
                    "source inventory verified; sweep is deterministic"
                    if getattr(hypothesis, "is_indicator_only", False)
                    else "quote found; relevance needs review"
                )
                source = f"{source_name} feed"
            else:
                status = "quote not found in source text"
                source = source_url or source_name
            citation_rows.append(
                {
                    "field": field,
                    "claim": citation["claim"],
                    "quote": quote,
                    "source": source,
                    "status": status,
                }
            )

    return citation_rows
