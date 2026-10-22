"""Regression tests for exact claim-to-source quote checks."""

from hecate_runner.claim_provenance import verify_claim_citations
from hecate_runner.hecate_client import HypothesisResult


def test_verifies_quote_from_feed_and_matching_claim_excerpt() -> None:
    feed = "Threat report: The actor used certutil to download the payload."
    claim = "The actor used certutil to download the payload."
    rows = verify_claim_citations(
        HypothesisResult(hypothesis=claim),
        [{"field": "hypothesis", "claim": "used certutil", "quote": "used certutil to download"}],
        feed,
        source_name="Example feed",
    )

    row = next(row for row in rows if row["field"] == "hypothesis")
    assert row["status"] == "quote found; relevance needs review"
    assert row["source"] == "Example feed feed"


def test_verifies_quote_from_fetched_primary_source() -> None:
    rows = verify_claim_citations(
        HypothesisResult(hypothesis="The actor used certutil."),
        [{"field": "hypothesis", "claim": "used certutil", "quote": "The actor used certutil."}],
        "A short feed summary.",
        primary_source_text="The actor used certutil.",
        source_url="https://example.com/report",
    )

    row = next(row for row in rows if row["field"] == "hypothesis")
    assert row["status"] == "quote found; relevance needs review"
    assert row["source"] == "https://example.com/report"


def test_rejects_quote_not_present_in_either_source() -> None:
    rows = verify_claim_citations(
        HypothesisResult(hypothesis="The actor used certutil."),
        [{"field": "hypothesis", "claim": "used certutil", "quote": "stole credentials"}],
        "The actor used certutil.",
    )

    row = next(row for row in rows if row["field"] == "hypothesis")
    assert row["status"] == "quote not found in source text"


def test_rejects_citation_claim_excerpt_missing_from_final_field() -> None:
    rows = verify_claim_citations(
        HypothesisResult(hypothesis="The actor used certutil."),
        [{"field": "hypothesis", "claim": "credential theft", "quote": "The actor used certutil."}],
        "The actor used certutil.",
    )

    row = next(row for row in rows if row["field"] == "hypothesis")
    assert row["status"] == "claim excerpt does not match final field"


def test_reports_claim_without_citation() -> None:
    rows = verify_claim_citations(
        HypothesisResult(hypothesis="The actor used certutil."),
        [],
        "The actor used certutil.",
    )

    row = next(row for row in rows if row["field"] == "hypothesis")
    assert row["status"] == "no exact claim citation supplied"
