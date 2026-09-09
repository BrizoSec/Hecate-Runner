"""The parked area: nothing the gate declines is ever lost."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.cti import CTIItem
from hecate_runner.parked_store import get_parked, list_parked, park, parked_dir, restore

ITEM = CTIItem(
    content="RSS: Week 33 roundup\nSummary: news.",
    source="rss",
    title="The Good, the Bad and the Ugly - Week 33",
    identifier="https://example-feed.test/p/33",
    source_url="https://example-feed.test/p/33",
)


def test_a_parked_item_keeps_its_content_whole(tmp_path: Path) -> None:
    """The provider cursor has already advanced, so this copy is the only
    one left -- a reference would not be recoverable."""
    park(tmp_path, ITEM, "commentary")
    stored = list_parked(tmp_path)[0]
    assert stored.content == ITEM.content
    assert stored.title == ITEM.title
    assert stored.source_url == ITEM.source_url


def test_the_reason_is_stored_for_the_reviewer(tmp_path: Path) -> None:
    park(tmp_path, ITEM, "publisher category 'company' is commentary")
    assert "company" in list_parked(tmp_path)[0].reason


def test_an_empty_park_is_not_an_error(tmp_path: Path) -> None:
    assert list_parked(tmp_path) == []


def test_items_come_back_newest_first(tmp_path: Path) -> None:
    """Ordered by parked_at, which carries microseconds -- park_id only has
    second resolution, so two items parked in the same second are ordered by
    when they were written, not by id."""
    park(tmp_path, ITEM, "a")
    park(tmp_path, CTIItem(content="second", source="rss", identifier="two"), "b")
    stamps = [i.parked_at for i in list_parked(tmp_path)]
    assert stamps == sorted(stamps, reverse=True)
    assert len(stamps) == 2


def test_lookup_by_full_id_and_by_prefix(tmp_path: Path) -> None:
    path = park(tmp_path, ITEM, "commentary")
    park_id = path.stem
    assert get_parked(tmp_path, park_id) is not None
    assert get_parked(tmp_path, park_id[:12]) is not None


def test_an_ambiguous_prefix_resolves_to_nothing(tmp_path: Path) -> None:
    """Better to say "no match" than to restore the wrong item."""
    park(tmp_path, ITEM, "a")
    park(tmp_path, CTIItem(content="second", source="rss", identifier="two"), "b")
    assert get_parked(tmp_path, "20") is None


def test_an_unknown_id_returns_nothing(tmp_path: Path) -> None:
    assert get_parked(tmp_path, "nope") is None


def test_restore_puts_the_content_on_the_file_queue(tmp_path: Path) -> None:
    park(tmp_path, ITEM, "commentary")
    item = list_parked(tmp_path)[0]
    restore(tmp_path, item)
    assert (tmp_path / "next.txt").read_text().strip() == ITEM.content.strip()


def test_restore_removes_it_from_the_park(tmp_path: Path) -> None:
    park(tmp_path, ITEM, "commentary")
    restore(tmp_path, list_parked(tmp_path)[0])
    assert list_parked(tmp_path) == []


def test_a_corrupt_parked_file_is_skipped_not_fatal(tmp_path: Path) -> None:
    park(tmp_path, ITEM, "commentary")
    (parked_dir(tmp_path) / "broken.json").write_text("{not json")
    assert len(list_parked(tmp_path)) == 1


def test_lookup_by_the_hash_half_of_the_id(tmp_path: Path) -> None:
    """The memorable half is the hash on the end, and that is what gets
    copied out of the listing."""
    park_id = park(tmp_path, ITEM, "commentary").stem
    assert get_parked(tmp_path, park_id.split("-")[1]) is not None


def test_an_empty_fragment_matches_nothing(tmp_path: Path) -> None:
    park(tmp_path, ITEM, "commentary")
    assert get_parked(tmp_path, "") is None
