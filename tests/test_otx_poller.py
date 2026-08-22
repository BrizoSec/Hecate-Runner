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
