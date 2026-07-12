"""RSS poller tests. RssProvider is mocked — no real HTTP calls."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sec7669 import rss_poller
from sec7669.config import Settings
from sec7669.cti.base import CTIItem
from sec7669.cti.rss import RssError, RssProvider


@pytest.fixture
def mock_rss_provider(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    mock_cls = MagicMock(return_value=MagicMock(spec=RssProvider))
    monkeypatch.setattr(rss_poller, "RssProvider", mock_cls)
    return mock_cls


def test_no_feed_urls_returns_error(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEC7669_RSS_FEED_URLS", "")
    empty_feed_settings = Settings(_env_file=None)  # type: ignore[call-arg]

    result = rss_poller.run_rss_poll(empty_feed_settings)
    assert result.error is not None
    assert "no feed urls" in result.error.lower()
    assert not result.ok


def test_queue_slot_occupied_skips(
    settings: Settings, workspace: Path, mock_rss_provider: MagicMock
) -> None:
    (workspace / "cti_queue" / "next.txt").write_text("existing intel")
    result = rss_poller.run_rss_poll(settings)
    assert result.skipped_queue_occupied
    assert result.ok
    mock_rss_provider.assert_not_called()


def test_no_new_entries(
    settings: Settings, workspace: Path, mock_rss_provider: MagicMock
) -> None:
    mock_rss_provider.return_value.next_item.return_value = None
    result = rss_poller.run_rss_poll(settings)
    assert result.routed == 0
    assert result.ok
    mock_rss_provider.return_value.close.assert_called_once()


def test_routes_entry_into_queue(
    settings: Settings, workspace: Path, mock_rss_provider: MagicMock
) -> None:
    item = CTIItem(
        content="RSS: test post",
        source="rss",
        identifier="https://example.com/post-1",
        metadata={
            "feed_url": "https://example.com/feed/",
            "entry_id": "https://example.com/post-1",
            "entry_title": "test post",
        },
    )
    mock_rss_provider.return_value.next_item.return_value = item

    result = rss_poller.run_rss_poll(settings)

    assert result.routed == 1
    assert result.routed_entry_ids == ["https://example.com/post-1"]
    assert result.ok
    assert (workspace / "cti_queue" / "next.txt").read_text() == "RSS: test post"
    mock_rss_provider.return_value.acknowledge.assert_called_once_with(item)
    mock_rss_provider.return_value.close.assert_called_once()


def test_rss_error_is_captured(
    settings: Settings, workspace: Path, mock_rss_provider: MagicMock
) -> None:
    mock_rss_provider.return_value.next_item.side_effect = RssError("boom")
    result = rss_poller.run_rss_poll(settings)
    assert result.error == "boom"
    assert not result.ok
    mock_rss_provider.return_value.close.assert_called_once()
