"""Tests for PendingQueryStore persistence."""

from __future__ import annotations

from pathlib import Path

from hecate_runner.query_execution import ProposedQuery
from hecate_runner.query_store import PendingQueryStore


def _query(hunt_id: str = "H-0001") -> ProposedQuery:
    return ProposedQuery(
        hunt_id=hunt_id,
        data_source="splunk",
        query_text="index=main | head 10",
        time_range_days=7,
        limit=100,
    )


def test_save_then_load_round_trips(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "pending")
    original = _query()
    store.save(original)

    loaded = store.load("H-0001")
    assert loaded == original


def test_load_missing_returns_none(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "pending")
    assert store.load("H-9999") is None


def test_save_creates_store_dir_if_missing(tmp_path: Path) -> None:
    store_dir = tmp_path / "does" / "not" / "exist" / "yet"
    store = PendingQueryStore(store_dir)
    store.save(_query())
    assert store_dir.exists()


def test_remove_deletes_the_file(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "pending")
    store.save(_query())
    store.remove("H-0001")
    assert store.load("H-0001") is None


def test_remove_missing_is_a_noop(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "pending")
    store.remove("H-9999")  # must not raise


def test_list_all_returns_every_saved_query(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "pending")
    store.save(_query("H-0001"))
    store.save(_query("H-0002"))
    store.save(_query("H-0003"))

    hunt_ids = {q.hunt_id for q in store.list_all()}
    assert hunt_ids == {"H-0001", "H-0002", "H-0003"}


def test_list_all_on_missing_dir_returns_empty(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "never_created")
    assert store.list_all() == []


def test_list_all_skips_corrupt_files(tmp_path: Path) -> None:
    store_dir = tmp_path / "pending"
    store = PendingQueryStore(store_dir)
    store.save(_query("H-0001"))

    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / "H-0002.json").write_text("{not valid json")

    results = store.list_all()
    assert len(results) == 1
    assert results[0].hunt_id == "H-0001"


def test_separate_hunts_do_not_collide(tmp_path: Path) -> None:
    store = PendingQueryStore(tmp_path / "pending")
    store.save(_query("H-0001"))
    store.save(_query("H-0002"))

    store.remove("H-0001")

    assert store.load("H-0001") is None
    assert store.load("H-0002") is not None
