"""Decide whether a CTI item is worth drafting a hunt from, without discarding it.

Three of the first fifteen drafts came from source material that is not threat
intelligence: a conference recap, a weekly news roundup, and a vendor post
about agentic SOCs. The empty case -- a blurb that is nothing but its own
metadata -- is handled in ``orchestrator.is_actionable``. This module covers
the harder one: an item that *has* prose, but whose prose is commentary.

**Why this parks rather than skips.** The two failure directions cost wildly
different amounts. A junk draft costs one review slot and is visible. A
wrongly-dropped item is gone: the cursor advances, nothing is logged as a
loss, and no one learns that a real campaign writeup was discarded. So the
gate never consumes anything -- a parked item is written to
``<cti_queue>/parked/`` in full and can be listed and restored.

That asymmetry is also why the rules below are deliberately narrow and
deterministic rather than clever. A model was measured on this exact task
first: 8/8 on hand-picked examples, then on 36 uncurated live entries it
parked 27, including "From Bing Search to Ransomware: Bumblebee and AdaptixC2
Delivery", "Cat's Got Your Files: Lynx Ransomware", and the BengalSEO writeup
that became H-0616 -- three unambiguous pieces of intelligence from the
highest-signal feed subscribed to. It also gave three different answers to
three entries of one monthly series. Recoverability makes such a gate
survivable, but it does not make it good, so it is not the gate used here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from hecate_runner.cti import CTIItem


@dataclass
class TriageVerdict:
    """Whether to park an item, and the reason a reviewer will read."""

    park: bool
    reason: str = ""


#: Publisher-declared categories that mark a post as commentary. Only
#: unambiguous ones: a category naming a recurring non-technical series, or
#: corporate/product content. Deliberately absent are plausible-looking but
#: mixed categories -- "Insights" covers Red Canary's monthly threat
#: intelligence summaries, "Security Operations" and "AI" cover real research.
_COMMENTARY_CATEGORIES = frozenset(
    {
        "the good, the bad and the ugly",
        "threat source newsletter",
        "company",
        "company news",
        "life at",
        "tool talk",
        "product",
        "product updates",
        "partners",
        "events",
        "careers",
    }
)

#: Title shapes for the feeds that declare no categories at all (Huntress and
#: SANS among those subscribed). Each requires a recurring-series or
#: explainer shape, not merely a topic word, so a real advisory that happens
#: to mention a conference is not caught.
_COMMENTARY_TITLE_PATTERNS = (
    re.compile(r"^the good, the bad and the ugly\b", re.IGNORECASE),
    re.compile(r"\bweek\s+\d{1,2}\s*\(20\d\d\)", re.IGNORECASE),
    re.compile(
        r"\b(?:black hat|def ?con|rsa conference|hacker summer camp)\b.{0,40}"
        r"\b(?:standouts?|recap|highlights?|takeaways?|what we learned)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"^\d{1,2}\s+\w+.{0,30}\b(?:standouts?|takeaways?|predictions?|trends)\b", re.IGNORECASE
    ),
    re.compile(r"^what is\b|^how to choose\b|\bbuyer'?s guide\b", re.IGNORECASE),
)


def _categories(item: CTIItem) -> list[str]:
    raw: Any = item.metadata.get("entry_tags") or []
    return [str(t).strip().lower() for t in raw if str(t).strip()]


def triage(item: CTIItem) -> TriageVerdict:
    """Park commentary; let everything else through.

    Errs toward drafting. An item is parked only on a positive signal -- a
    publisher category naming a commentary series, or a title in a recurring
    non-technical shape -- never on the absence of one.
    """
    # A provider flags intel that expired while it waited for a draft slot.
    # Parking it is the point: silently skipping it is how OTX lost 23
    # high-signal pulses with no record that they existed.
    aged_out = item.metadata.get("aged_out")
    if aged_out:
        return TriageVerdict(True, f"aged out: {aged_out}")

    for category in _categories(item):
        if category in _COMMENTARY_CATEGORIES:
            return TriageVerdict(
                True, f"publisher category {category!r} is commentary, not intelligence"
            )

    title = (item.title or "").strip()
    for pattern in _COMMENTARY_TITLE_PATTERNS:
        if pattern.search(title):
            return TriageVerdict(
                True, f"title matches a recurring commentary shape ({pattern.pattern[:44]}...)"
            )

    return TriageVerdict(False)


def source_quality_verdict(item: CTIItem) -> TriageVerdict | None:
    """Apply provider-declared evidence limits independently of article triage.

    Provider metadata is the reliable signal for machine-generated sample
    and archive records: a prose-shaped blurb must not upgrade those records
    into behavioral reporting. Malware samples with real hashes remain
    eligible for the deterministic indicator-sweep route; repository archive
    metadata without endpoint indicators is held for a richer source.
    """
    profile = str(item.metadata.get("evidence_profile", "")).strip().lower()
    if profile == "sample_metadata":
        indicators = item.metadata.get("indicators") or {}
        has_indicators = (
            any(bool(values) for values in indicators.values())
            if isinstance(indicators, dict)
            else bool(indicators)
        )
        if has_indicators:
            return TriageVerdict(False)
        return TriageVerdict(
            True,
            "sample catalog entry has no routable indicators and no reported behavior",
        )
    if profile == "archive_metadata":
        return TriageVerdict(
            True,
            "repository archive metadata names files but contains no extracted behavior or endpoint indicators",
        )
    return None
