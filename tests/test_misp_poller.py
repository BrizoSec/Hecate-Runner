"""MISP poller tests. MispProvider is mocked — no real HTTP calls."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from hecate_runner import misp_poller
from hecate_runner.config import Settings
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.misp import MispError, MispProvider


@pytest.fixture
def mock_misp_provider(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    mock_cls = MagicMock(return_value=MagicMock(spec=MispProvider))
    monkeypatch.setattr(misp_poller, "MispProvider", mock_cls)
    return mock_cls


def _misp_settings(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv("MISP_BASE_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "test-key")
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_missing_base_url_returns_error(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MISP_API_KEY", "test-key")
    misp_settings = Settings(_env_file=None)  # type: ignore[call-arg]
    result = misp_poller.run_misp_poll(misp_settings)
    assert result.error is not None
    assert not result.ok


def test_missing_api_key_returns_error(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_BASE_URL", "https://misp.example.com")
    misp_settings = Settings(_env_file=None)  # type: ignore[call-arg]
    result = misp_poller.run_misp_poll(misp_settings)
    assert result.error is not None
    assert not result.ok


def test_queue_slot_occupied_skips(
    settings: Settings,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_misp_provider: MagicMock,
) -> None:
    misp_settings = _misp_settings(settings, monkeypatch)
    (workspace / "cti_queue" / "next.txt").write_text("existing intel")
    result = misp_poller.run_misp_poll(misp_settings)
    assert result.skipped_queue_occupied
    assert result.ok
    mock_misp_provider.assert_not_called()


def test_no_new_events(
    settings: Settings,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_misp_provider: MagicMock,
) -> None:
    misp_settings = _misp_settings(settings, monkeypatch)
    mock_misp_provider.return_value.next_item.return_value = None
    result = misp_poller.run_misp_poll(misp_settings)
    assert result.routed == 0
    assert result.ok
    mock_misp_provider.return_value.close.assert_called_once()


def test_routes_event_into_queue(
    settings: Settings,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_misp_provider: MagicMock,
) -> None:
    misp_settings = _misp_settings(settings, monkeypatch)
    item = CTIItem(
        content="MISP Event: test",
        source="misp",
        identifier="event-uuid-1",
        metadata={
            "event_uuid": "event-uuid-1",
            "event_timestamp": "1234567890",
            "event_info": "test",
        },
    )
    mock_misp_provider.return_value.next_item.return_value = item

    result = misp_poller.run_misp_poll(misp_settings)

    assert result.routed == 1
    assert result.routed_event_uuids == ["event-uuid-1"]
    assert result.ok
    assert (workspace / "cti_queue" / "next.txt").read_text() == "MISP Event: test"
    mock_misp_provider.return_value.acknowledge.assert_called_once_with(item)
    mock_misp_provider.return_value.close.assert_called_once()


def test_misp_error_is_captured(
    settings: Settings,
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    mock_misp_provider: MagicMock,
) -> None:
    misp_settings = _misp_settings(settings, monkeypatch)
    mock_misp_provider.return_value.next_item.side_effect = MispError("boom")
    result = misp_poller.run_misp_poll(misp_settings)
    assert result.error == "boom"
    assert not result.ok
    mock_misp_provider.return_value.close.assert_called_once()
