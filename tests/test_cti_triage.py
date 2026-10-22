"""Triage rules: park commentary, never park intelligence.

The must-keep cases are the point. A model gate was measured on this task
first and parked "Cat's Got Your Files: Lynx Ransomware", "From Bing Search to
Ransomware: Bumblebee and AdaptixC2 Delivery" and the BengalSEO writeup that
became H-0616 -- so those titles are pinned here as regressions.
"""

from __future__ import annotations

import pytest

from hecate_runner.cti import CTIItem
from hecate_runner.cti_triage import source_quality_verdict, triage


def _item(title: str = "", tags: list[str] | None = None) -> CTIItem:
    return CTIItem(content="x", source="rss", title=title, metadata={"entry_tags": tags or []})


# --- Parked: publisher said so ---------------------------------------------


@pytest.mark.parametrize(
    "category",
    [
        "The Good, the Bad and the Ugly",
        "Threat Source newsletter",
        "Company",
        "Product Updates",
        "Tool Talk",
    ],
)
def test_a_commentary_category_is_parked(category: str) -> None:
    verdict = triage(_item("Some post", [category]))
    assert verdict.park is True
    assert category.lower() in verdict.reason


def test_categories_are_matched_case_insensitively() -> None:
    assert triage(_item("x", ["COMPANY"])).park is True


@pytest.mark.parametrize(
    "category", ["Malware", "Threat Research", "ransomware", "Insights", "Security Operations"]
)
def test_a_research_category_is_not_parked(category: str) -> None:
    """ "Insights" covers Red Canary's monthly intelligence summaries and
    "Security Operations" covers real research, so neither is denied."""
    assert triage(_item("Some post", [category])).park is False


# --- Parked: title shape, for feeds that publish no categories -------------


@pytest.mark.parametrize(
    "title",
    [
        "The Good, the Bad and the Ugly in Cybersecurity - Week 33 (2026)",
        "10 Hacker Summer Camp Standouts at Black Hat and DEF CON",
        "Black Hat 2026 recap: what we saw",
        "What is Managed EDR?",
        "How to choose a managed detection provider",
    ],
)
def test_a_commentary_title_is_parked_without_categories(title: str) -> None:
    assert triage(_item(title)).park is True


# --- Never parked -----------------------------------------------------------


@pytest.mark.parametrize(
    "title",
    [
        "Cat's Got Your Files: Lynx Ransomware",
        "From Bing Search to Ransomware: Bumblebee and AdaptixC2 Delivery",
        "BengalSEO Part 1: Anatomy of the Operation",
        "Apache ActiveMQ Exploit Leads to LockBit Ransomware",
        "Critical N-able N-central Vulnerability and Active Exploitation",
        "ClearFake WebDAV infection chain delivers Amatera stealer",
    ],
)
def test_real_intelligence_is_never_parked(title: str) -> None:
    assert triage(_item(title)).park is False


def test_a_conference_word_alone_does_not_park() -> None:
    """The pattern needs a recurring-recap shape, not just a topic word --
    otherwise a genuine advisory mentioning a conference would be held back."""
    assert triage(_item("What We Learned Hunting APT29 in Azure")).park is False
    assert triage(_item("Threat actors exploit a flaw disclosed at Black Hat")).park is False


def test_an_item_with_no_title_and_no_tags_is_not_parked() -> None:
    """Absence of signal is never a reason to hold something back."""
    assert triage(_item()).park is False


def test_non_rss_items_pass_through() -> None:
    """MISP and OTX carry no publisher categories; they must not be gated by
    the absence of them."""
    item = CTIItem(content="MISP Event: X\nSummary: prose", source="misp", title="", metadata={})
    assert triage(item).park is False


def test_sample_metadata_with_hash_is_routed_to_indicator_sweep() -> None:
    item = CTIItem(
        content="sample catalog record",
        source="malwarebazaar",
        metadata={
            "evidence_profile": "sample_metadata",
            "indicators": {"sha256": ["a" * 64]},
        },
    )

    verdict = source_quality_verdict(item)

    assert verdict is not None
    assert verdict.park is False


def test_sample_metadata_without_indicators_is_parked() -> None:
    item = CTIItem(
        content="sample catalog record",
        source="malwarebazaar",
        metadata={"evidence_profile": "sample_metadata", "indicators": {}},
    )

    verdict = source_quality_verdict(item)

    assert verdict is not None
    assert verdict.park is True
    assert "no routable indicators" in verdict.reason


def test_repository_archive_metadata_is_parked() -> None:
    item = CTIItem(
        content="repository archive record",
        source="vxunderground",
        metadata={"evidence_profile": "archive_metadata", "files": ["Windows/sample.7z"]},
    )

    verdict = source_quality_verdict(item)

    assert verdict is not None
    assert verdict.park is True
    assert "no extracted behavior" in verdict.reason
