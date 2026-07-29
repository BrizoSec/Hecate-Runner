"""MultiProvider tests. Sub-providers are simple in-memory fakes — no network."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sec7669.config import Settings
from sec7669.cti import MultiProvider, get_provider
from sec7669.cti.base import CTIItem, CTIProvider
from sec7669.cti.multi import MultiCursorState, MultiProviderError


class _FakeProvider(CTIProvider):
    """In-memory stand-in for a real CTI source."""

    def __init__(self, name: str, items: list[CTIItem | None] | None = None, *, fail: bool = False):
        self.name = name
        self._items = list(items or [])
        self.fail = fail
        self.acknowledged: list[CTIItem] = []

    def next_item(self) -> CTIItem | None:
        if self.fail:
            raise RuntimeError(f"{self.name} is down")
        if not self._items:
            return None
        return self._items.pop(0)

    def acknowledge(self, item: CTIItem) -> None:
        self.acknowledged.append(item)


def _item(source: str, content: str) -> CTIItem:
    return CTIItem(content=content, source=source, received_at=datetime.now(UTC))


# --- Construction ------------------------------------------------------------


def test_requires_at_least_one_provider(tmp_path: Path) -> None:
    with pytest.raises(MultiProviderError, match="At least one"):
        MultiProvider(providers=[], cursor_file=tmp_path / "cursor.json")


def test_rejects_duplicate_provider_names(tmp_path: Path) -> None:
    a = _FakeProvider("rss")
    b = _FakeProvider("rss")
    with pytest.raises(MultiProviderError, match="Duplicate"):
        MultiProvider(providers=[a, b], cursor_file=tmp_path / "cursor.json")


# --- next_item / rotation -----------------------------------------------------


def test_round_robins_across_cycles(tmp_path: Path) -> None:
    rss = _FakeProvider("rss", [_item("rss", "rss-1"), _item("rss", "rss-2")])
    otx = _FakeProvider("otx", [_item("otx", "otx-1")])
    provider = MultiProvider(providers=[rss, otx], cursor_file=tmp_path / "cursor.json")

    first = provider.next_item()
    assert first is not None and first.content == "rss-1"

    second = provider.next_item()
    assert second is not None and second.content == "otx-1"

    # Rotation is back to rss's turn (0 -> 1 -> 0); it still has a queued
    # item, so no fallback to another source is needed this cycle.
    third = provider.next_item()
    assert third is not None and third.content == "rss-2"


def test_skips_source_with_nothing_new(tmp_path: Path) -> None:
    empty = _FakeProvider("misp", [])
    rss = _FakeProvider("rss", [_item("rss", "rss-1")])
    provider = MultiProvider(providers=[empty, rss], cursor_file=tmp_path / "cursor.json")

    item = provider.next_item()
    assert item is not None
    assert item.content == "rss-1"


def test_returns_none_when_all_empty(tmp_path: Path) -> None:
    a = _FakeProvider("rss", [])
    b = _FakeProvider("otx", [])
    provider = MultiProvider(providers=[a, b], cursor_file=tmp_path / "cursor.json")
    assert provider.next_item() is None


def test_isolates_failing_sub_provider(tmp_path: Path) -> None:
    broken = _FakeProvider("misp", fail=True)
    rss = _FakeProvider("rss", [_item("rss", "rss-1")])
    provider = MultiProvider(providers=[broken, rss], cursor_file=tmp_path / "cursor.json")

    item = provider.next_item()
    assert item is not None
    assert item.content == "rss-1"


# --- acknowledge ---------------------------------------------------------------


def test_acknowledge_routes_to_correct_sub_provider(tmp_path: Path) -> None:
    rss = _FakeProvider("rss")
    otx = _FakeProvider("otx")
    provider = MultiProvider(providers=[rss, otx], cursor_file=tmp_path / "cursor.json")

    item = _item("otx", "otx pulse")
    provider.acknowledge(item)

    assert otx.acknowledged == [item]
    assert rss.acknowledged == []


def test_acknowledge_unknown_source_does_not_raise(tmp_path: Path) -> None:
    rss = _FakeProvider("rss")
    provider = MultiProvider(providers=[rss], cursor_file=tmp_path / "cursor.json")
    provider.acknowledge(_item("misp", "orphaned"))  # misp not configured
    assert rss.acknowledged == []


# --- Cursor persistence --------------------------------------------------------


def test_cursor_persists_across_instances(tmp_path: Path) -> None:
    cursor_file = tmp_path / "cursor.json"
    rss = _FakeProvider("rss", [_item("rss", "rss-1")])
    otx = _FakeProvider("otx", [_item("otx", "otx-1")])
    MultiProvider(providers=[rss, otx], cursor_file=cursor_file).next_item()

    # A fresh instance (new process, same disk state) should honor the
    # persisted rotation rather than restarting from provider 0.
    state = MultiCursorState.load(cursor_file)
    assert state.next_index == 1

    rss2 = _FakeProvider("rss", [_item("rss", "rss-2")])
    otx2 = _FakeProvider("otx", [_item("otx", "otx-2")])
    second = MultiProvider(providers=[rss2, otx2], cursor_file=cursor_file).next_item()
    assert second is not None and second.content == "otx-2"


def test_corrupt_cursor_file_resets(tmp_path: Path) -> None:
    cursor_file = tmp_path / "cursor.json"
    cursor_file.write_text("not json")
    state = MultiCursorState.load(cursor_file)
    assert state.next_index == 0


# --- Factory -------------------------------------------------------------------


def test_factory_builds_multi_provider(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEC7669_CTI_PROVIDER", "multi")
    monkeypatch.setenv("SEC7669_CTI_MULTI_PROVIDERS", "rss,file")
    multi_settings = Settings(_env_file=None)  # type: ignore[call-arg]

    provider = get_provider("multi", settings=multi_settings)
    assert isinstance(provider, MultiProvider)
    assert {p.name for p in provider.providers} == {"rss", "file"}


def test_factory_rejects_empty_provider_list(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEC7669_CTI_MULTI_PROVIDERS", "")
    empty_settings = Settings(_env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="at least one provider"):
        get_provider("multi", settings=empty_settings)


def test_factory_rejects_self_reference(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEC7669_CTI_MULTI_PROVIDERS", "rss,multi")
    settings_with_self = Settings(_env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="cannot include 'multi'"):
        get_provider("multi", settings=settings_with_self)
