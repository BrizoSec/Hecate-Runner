"""OTX poller tests. OtxProvider is mocked — no real HTTP calls."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner import otx_poller
from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.otx import OtxError, OtxProvider


@pytest.fixture
def mock_otx_provider(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    mock_cls = MagicMock(return_value=MagicMock(spec=OtxProvider))
    monkeypatch.setattr(otx_poller, "OtxProvider", mock_cls)
    return mock_cls


def test_missing_api_key_returns_error(settings: Settings) -> None:
    result = otx_poller.run_otx_poll(settings)
    assert result.error == "OTX_API_KEY is not set"
    assert not result.ok


def test_queue_slot_occupied_skips(
    otx_settings: Settings, workspace: Path, mock_otx_provider: MagicMock
) -> None:
    (workspace / "cti_queue" / "next.txt").write_text("existing intel")
    result = otx_poller.run_otx_poll(otx_settings)
    assert result.skipped_queue_occupied
    assert result.ok
    mock_otx_provider.assert_not_called()


def test_no_new_pulses(
    otx_settings: Settings, workspace: Path, mock_otx_provider: MagicMock
) -> None:
    mock_otx_provider.return_value.next_item.return_value = None
    result = otx_poller.run_otx_poll(otx_settings)
    assert result.routed == 0
    assert result.ok
    mock_otx_provider.return_value.close.assert_called_once()


def test_routes_pulse_into_queue(
    otx_settings: Settings, workspace: Path, mock_otx_provider: MagicMock
) -> None:
    item = CTIItem(
        content="OTX Pulse: test",
        source="otx",
        identifier="pulse-1",
        metadata={
            "pulse_id": "pulse-1",
            "pulse_modified": "2026-07-01T00:00:00.000000",
            "pulse_name": "test",
        },
    )
    mock_otx_provider.return_value.next_item.return_value = item

    result = otx_poller.run_otx_poll(otx_settings)

    assert result.routed == 1
    assert result.routed_pulse_ids == ["pulse-1"]
    assert result.ok
    assert (workspace / "cti_queue" / "next.txt").read_text() == "OTX Pulse: test"
    mock_otx_provider.return_value.acknowledge.assert_called_once_with(item)
    mock_otx_provider.return_value.close.assert_called_once()


def test_otx_error_is_captured(
    otx_settings: Settings, workspace: Path, mock_otx_provider: MagicMock
) -> None:
    mock_otx_provider.return_value.next_item.side_effect = OtxError("boom")
    result = otx_poller.run_otx_poll(otx_settings)
    assert result.error == "boom"
    assert not result.ok
    mock_otx_provider.return_value.close.assert_called_once()


# --- Indicator values reach the blurb (G8) ---------------------------------

from hecate_runner.cti.otx import _indicator_detail_lines, _pulse_to_blurb  # noqa: E402


def _pulse(indicators, **extra):
    base = {"name": "PEEP: A Browser RAT", "description": "A toolkit.", "indicators": indicators}
    base.update(extra)
    return base


def _hashes(n):
    return [{"type": "FileHash-SHA256", "indicator": f"{i:064x}"} for i in range(n)]


def test_concrete_values_reach_the_blurb():
    """The counts line said 13 hashes existed without naming one, so the
    hunt built from it contained none of them."""
    blurb = _pulse_to_blurb(_pulse(_hashes(3)))
    assert "Key indicators:" in blurb
    assert f"{0:064x}" in blurb


def test_the_counts_line_survives_alongside_the_values():
    blurb = _pulse_to_blurb(_pulse(_hashes(3)))
    assert "Indicators (3 total): FileHash-SHA256 (3)" in blurb


def test_a_bulk_dump_is_still_summarised_as_counts_only():
    """Past the ceiling the list is a feed, not tradecraft."""
    blurb = _pulse_to_blurb(_pulse(_hashes(41)))
    assert "Indicators (41 total)" in blurb
    assert "Key indicators:" not in blurb


def test_values_are_capped_per_type_and_the_elision_is_reported():
    lines = _indicator_detail_lines(_pulse(_hashes(12)))
    rendered = "\n".join(lines)
    assert "(+2 more)" in rendered


def test_cves_are_named_even_though_sigma_cannot_match_them():
    """Naming the CVE the source cited is what lets the audit tell it from
    an invented one."""
    blurb = _pulse_to_blurb(_pulse([{"type": "CVE", "indicator": "CVE-2026-4021"}, *_hashes(1)]))
    assert "CVE-2026-4021" in blurb


def test_the_rendered_shape_matches_the_misp_provider():
    """hunt_audit and the grounding audit already parse the MISP shape."""
    lines = _indicator_detail_lines(_pulse([{"type": "domain", "indicator": "api.wiresguard.com"}]))
    assert lines[0] == "Key indicators:"
    assert lines[1] == "  domain: api.wiresguard.com"


def test_a_pulse_with_no_indicators_adds_no_section():
    assert _indicator_detail_lines(_pulse([])) == []
    assert "Key indicators:" not in _pulse_to_blurb(_pulse([]))


def test_malformed_indicator_entries_are_skipped_not_fatal():
    lines = _indicator_detail_lines(
        _pulse(["not-a-dict", {"type": "", "indicator": "x"}, {"type": "domain", "indicator": ""}])
    )
    assert lines == []
