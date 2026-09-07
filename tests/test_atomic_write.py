"""Tests for the shared atomic-write helper used by state.py, query_store.py,
and the CTI cursor files."""

from __future__ import annotations

from pathlib import Path

import pytest

from hecate_runner.atomic_write import DEFAULT_FILE_MODE, atomic_write_text


def test_writes_content(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    atomic_write_text(path, '{"a": 1}')
    assert path.read_text() == '{"a": 1}'


def test_creates_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "out.json"
    atomic_write_text(path, "content")
    assert path.read_text() == "content"


def test_overwrites_existing_file_completely(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    path.write_text("old content that is much longer than the new content")
    atomic_write_text(path, "new")
    assert path.read_text() == "new"


def test_no_leftover_temp_files(tmp_path: Path) -> None:
    path = tmp_path / "out.json"
    atomic_write_text(path, "content")
    remaining = list(tmp_path.iterdir())
    assert remaining == [path]


def test_failure_during_rename_leaves_original_file_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the final atomic rename fails, the destination file must be
    exactly as it was before -- never truncated or partially overwritten,
    which is the entire point of writing to a temp file first and only
    swapping it in at the very end."""
    import os

    path = tmp_path / "out.json"
    path.write_text("original content")

    def failing_replace(*args: object, **kwargs: object) -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError, match="simulated disk failure"):
        atomic_write_text(path, "new content")

    assert path.read_text() == "original content"
    # The failed temp file must not be left behind either.
    assert list(tmp_path.iterdir()) == [path]


def test_failure_leaves_no_temp_file_when_destination_never_existed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    path = tmp_path / "out.json"

    def failing_replace(*args: object, **kwargs: object) -> None:
        raise OSError("simulated disk failure")

    monkeypatch.setattr(os, "replace", failing_replace)

    with pytest.raises(OSError):
        atomic_write_text(path, "content")

    assert not path.exists()
    assert list(tmp_path.iterdir()) == []


def test_defaults_to_ordinary_file_permissions(tmp_path: Path) -> None:
    """mkstemp's 0o600 was an artifact of the temp file, not a choice -- a
    file written through this helper should look like any other file."""
    plain = tmp_path / "plain.json"
    plain.write_text("{}")
    path = tmp_path / "state.json"
    atomic_write_text(path, "{}")
    assert path.stat().st_mode & 0o777 == plain.stat().st_mode & 0o777


def test_explicit_mode_overrides_the_default(tmp_path: Path) -> None:
    path = tmp_path / "secret.json"
    atomic_write_text(path, "{}", mode=0o600)
    assert path.stat().st_mode & 0o777 == 0o600


def test_mode_is_applied_before_the_rename(tmp_path: Path) -> None:
    path = tmp_path / "counter"
    atomic_write_text(path, "7\n", mode=0o644)
    assert path.stat().st_mode & 0o777 == 0o644


def test_default_file_mode_matches_a_plain_write(tmp_path: Path) -> None:
    """DEFAULT_FILE_MODE must equal what an ordinary file creation produces
    under the current umask -- that is the whole point of passing it."""
    plain = tmp_path / "plain.txt"
    plain.write_text("x")
    atomic = tmp_path / "atomic.txt"
    atomic_write_text(atomic, "x", mode=DEFAULT_FILE_MODE)
    assert atomic.stat().st_mode & 0o777 == plain.stat().st_mode & 0o777
