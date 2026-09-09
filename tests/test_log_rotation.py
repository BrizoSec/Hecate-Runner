"""Tests for copy-and-truncate log rotation.

The deployment detail that shapes all of this: systemd is a second writer to
the orchestrator log (`StandardOutput=append:`) and holds its descriptor for
the whole run. So the property that matters is not "the file got smaller" but
"the inode survived" — a rename would silently split a run's output across two
files, which is the failure the stdlib RotatingFileHandler would have caused.
"""

from __future__ import annotations

from pathlib import Path

from hecate_runner.log_rotation import rotate_log_if_needed


def _log(tmp_path: Path, size: int) -> Path:
    path = tmp_path / "orchestrator.log"
    path.write_text("x" * size)
    return path


def test_does_nothing_below_the_threshold(tmp_path: Path) -> None:
    path = _log(tmp_path, 100)
    assert rotate_log_if_needed(path, max_bytes=1000, backup_count=3) is False
    assert path.read_text() == "x" * 100


def test_rotates_above_the_threshold(tmp_path: Path) -> None:
    path = _log(tmp_path, 2000)
    assert rotate_log_if_needed(path, max_bytes=1000, backup_count=3) is True
    assert path.stat().st_size == 0
    assert (tmp_path / "orchestrator.log.1").read_text() == "x" * 2000


def test_the_inode_survives_rotation(tmp_path: Path) -> None:
    """The whole reason this is not a RotatingFileHandler.

    systemd opened this file before the process started. If rotation replaces
    the inode, everything systemd writes for the rest of the run lands in the
    archive while Python writes to the new file -- split output, no error.
    """
    path = _log(tmp_path, 2000)
    before = path.stat().st_ino
    rotate_log_if_needed(path, max_bytes=1000, backup_count=3)
    assert path.stat().st_ino == before


def test_an_already_open_append_handle_keeps_writing_to_the_live_file(tmp_path: Path) -> None:
    """Simulates systemd's descriptor: opened before rotation, still correct
    after it, and writing at offset 0 rather than leaving a sparse gap."""
    path = _log(tmp_path, 2000)
    with open(path, "a") as pre_existing:
        rotate_log_if_needed(path, max_bytes=1000, backup_count=3)
        pre_existing.write("after rotation\n")
        pre_existing.flush()

    assert path.read_text() == "after rotation\n"


def test_backups_shift_and_the_oldest_is_dropped(tmp_path: Path) -> None:
    path = tmp_path / "orchestrator.log"
    for index, marker in ((1, "one"), (2, "two")):
        (tmp_path / f"orchestrator.log.{index}").write_text(marker)
    path.write_text("current" + "x" * 2000)

    rotate_log_if_needed(path, max_bytes=1000, backup_count=2)

    assert (tmp_path / "orchestrator.log.1").read_text().startswith("current")
    assert (tmp_path / "orchestrator.log.2").read_text() == "one"
    # "two" was the oldest kept copy and falls off the end.
    assert not (tmp_path / "orchestrator.log.3").exists()


def test_zero_backups_truncates_without_keeping_history(tmp_path: Path) -> None:
    path = _log(tmp_path, 2000)
    assert rotate_log_if_needed(path, max_bytes=1000, backup_count=0) is True
    assert path.stat().st_size == 0
    assert not (tmp_path / "orchestrator.log.1").exists()


def test_zero_max_bytes_disables_rotation(tmp_path: Path) -> None:
    path = _log(tmp_path, 10_000)
    assert rotate_log_if_needed(path, max_bytes=0, backup_count=3) is False
    assert path.stat().st_size == 10_000


def test_a_missing_log_is_not_an_error(tmp_path: Path) -> None:
    assert rotate_log_if_needed(tmp_path / "absent.log", max_bytes=10, backup_count=1) is False


def test_rotation_failure_never_raises(tmp_path: Path, monkeypatch) -> None:
    """A log that cannot be rotated is a far smaller problem than a hunt cycle
    that dies on the way to doing real work."""
    path = _log(tmp_path, 2000)

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("hecate_runner.log_rotation.shutil.copy2", boom)
    assert rotate_log_if_needed(path, max_bytes=1000, backup_count=3) is False
    # The live log is untouched rather than half-rotated.
    assert path.stat().st_size == 2000


def test_second_rotation_is_a_no_op_while_the_file_is_small(tmp_path: Path) -> None:
    path = _log(tmp_path, 2000)
    assert rotate_log_if_needed(path, max_bytes=1000, backup_count=3) is True
    assert rotate_log_if_needed(path, max_bytes=1000, backup_count=3) is False
    # The first archive is not overwritten by an empty second one.
    assert (tmp_path / "orchestrator.log.1").stat().st_size == 2000


def test_the_lock_file_is_not_mistaken_for_a_backup(tmp_path: Path) -> None:
    path = _log(tmp_path, 2000)
    rotate_log_if_needed(path, max_bytes=1000, backup_count=3)
    lock = tmp_path / "orchestrator.log.rotate.lock"
    assert lock.exists()
    assert (tmp_path / "orchestrator.log.1").read_text() == "x" * 2000


def test_rotation_preserves_content_exactly(tmp_path: Path) -> None:
    path = tmp_path / "orchestrator.log"
    content = "\n".join(f"2026-09-08 [INFO] line {i}" for i in range(200))
    path.write_text(content)
    rotate_log_if_needed(path, max_bytes=100, backup_count=1)
    assert (tmp_path / "orchestrator.log.1").read_text() == content


def test_uses_configured_settings_end_to_end(tmp_path: Path) -> None:
    """Guards the wiring, not the algorithm: the settings must actually reach
    the rotation call in _configure_logging."""
    from hecate_runner.cli import _configure_logging
    from hecate_runner.config import Settings

    settings = Settings(_env_file=None, hecate_workspace=tmp_path)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    settings.log_file.write_text("x" * 4096)

    object.__setattr__(settings, "log_max_bytes", 1024)
    object.__setattr__(settings, "log_backup_count", 1)
    _configure_logging(settings, to_stdout=False)

    assert settings.log_file.with_name(settings.log_file.name + ".1").exists()
