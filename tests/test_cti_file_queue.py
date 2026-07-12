"""FileQueueProvider tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sec7669.config import Settings
from sec7669.cti import FileQueueProvider, MispProvider, get_provider
from sec7669.cti.base import CTIItem


def test_returns_none_when_empty(tmp_path: Path) -> None:
    provider = FileQueueProvider(queue_dir=tmp_path / "q")
    provider.ensure_dirs()
    assert provider.next_item() is None


def test_returns_none_for_empty_file(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    (q / "next.txt").write_text("   \n\n")
    provider = FileQueueProvider(queue_dir=q)
    assert provider.next_item() is None


def test_reads_and_returns_content(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    (q / "next.txt").write_text("APT actor X observed")
    provider = FileQueueProvider(queue_dir=q)
    item = provider.next_item()
    assert item is not None
    assert item.content == "APT actor X observed"
    assert item.source == "file"


def test_acknowledge_archives(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    (q / "next.txt").write_text("some intel")
    provider = FileQueueProvider(queue_dir=q)
    item = provider.next_item()
    assert item is not None
    provider.acknowledge(item)
    assert not (q / "next.txt").exists()
    processed = list((q / "processed").glob("cti-*.txt"))
    assert len(processed) == 1
    assert processed[0].read_text() == "some intel"


def test_acknowledge_when_no_file(tmp_path: Path) -> None:
    q = tmp_path / "q"
    q.mkdir()
    provider = FileQueueProvider(queue_dir=q)
    # Should not raise even if the file was already removed
    provider.acknowledge(CTIItem(content="stale", received_at=datetime.now(UTC)))


def test_factory_returns_file_provider(settings: Settings) -> None:
    provider = get_provider("file", settings=settings)
    assert isinstance(provider, FileQueueProvider)


def test_factory_returns_misp_provider(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISP_BASE_URL", "https://misp.example.com")
    monkeypatch.setenv("MISP_API_KEY", "test-key")
    misp_settings = Settings(_env_file=None)  # type: ignore[call-arg]
    provider = get_provider("misp", settings=misp_settings)
    assert isinstance(provider, MispProvider)


def test_factory_unknown_raises(settings: Settings) -> None:
    try:
        get_provider("bigquery", settings=settings)
    except ValueError as e:
        assert "bigquery" in str(e)
    else:
        raise AssertionError("expected ValueError")
