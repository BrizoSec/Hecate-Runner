"""Unit tests for VX-Underground CTI provider."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hecate_runner.config import Settings
from hecate_runner.cti import get_provider
from hecate_runner.cti.vxunderground import (
    VxUndergroundCursorState,
    VxUndergroundProvider,
)

SAMPLE_ATOM_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>tag:github.com,2008:Grit::Commit/1234567890abcdef1234567890abcdef12345678</id>
    <link type="text/html" rel="alternate" href="https://github.com/vxunderground/MalwareSourceCode/commit/1234567890abcdef1234567890abcdef12345678"/>
    <title>Create MacOS.Stealer.Banshee.7z</title>
    <updated>2026-10-21T01:00:00Z</updated>
  </entry>
  <entry>
    <id>tag:github.com,2008:Grit::Commit/abcdef1234567890abcdef1234567890abcdef12</id>
    <link type="text/html" rel="alternate" href="https://github.com/vxunderground/MalwareSourceCode/commit/abcdef1234567890abcdef1234567890abcdef12"/>
    <title>Upload Windows.Ransomware.LockBit.7z</title>
    <updated>2026-10-20T22:00:00Z</updated>
  </entry>
</feed>
"""

SAMPLE_PATCH_DATA = """From 1234567890abcdef1234567890abcdef12345678 Mon Sep 17 00:00:00 2001
Subject: [PATCH] Create MacOS.Stealer.Banshee.7z
---
 MacOS/MacOS.Stealer.Banshee.7z | Bin 0 -> 11791 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 MacOS/MacOS.Stealer.Banshee.7z

diff --git a/MacOS/MacOS.Stealer.Banshee.7z b/MacOS/MacOS.Stealer.Banshee.7z
new file mode 100644
index 0000000000000000000000000000000000000000..6d88d0ac05b98b9a4951182dda661f5b9cd9ca03
"""


def test_cursor_state_persistence(tmp_path: Path) -> None:
    cursor_file = tmp_path / "vx_cursor.json"
    state = VxUndergroundCursorState.from_file(cursor_file)
    assert state.seen_commits == []

    c1 = "1234567890abcdef1234567890abcdef12345678"
    state.record_commit(c1, cursor_file)
    assert c1 in state.seen_commits
    assert cursor_file.exists()

    # Reload from file
    reloaded = VxUndergroundCursorState.from_file(cursor_file)
    assert c1 in reloaded.seen_commits

    # Duplicate check
    reloaded.record_commit(c1, cursor_file)
    assert len(reloaded.seen_commits) == 1


def test_atom_feed_and_patch_parsing(tmp_path: Path) -> None:
    cursor_file = tmp_path / "vx_cursor.json"
    provider = VxUndergroundProvider(
        workspace=tmp_path,
        cursor_file=cursor_file,
    )

    mock_atom_resp = MagicMock()
    mock_atom_resp.read.return_value = SAMPLE_ATOM_FEED.encode("utf-8")
    mock_atom_resp.__enter__.return_value = mock_atom_resp

    mock_patch_resp = MagicMock()
    mock_patch_resp.read.return_value = SAMPLE_PATCH_DATA.encode("utf-8")
    mock_patch_resp.__enter__.return_value = mock_patch_resp

    def mock_urlopen(req, *args, **kwargs):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith(".patch"):
            return mock_patch_resp
        return mock_atom_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        item = provider.next_item()
        assert item is not None
        assert item.source == "vxunderground"
        assert item.identifier == "1234567890abcdef1234567890abcdef12345678"
        assert "Banshee" in item.title
        assert item.metadata["platform"] == "MacOS"
        assert "MacOS/MacOS.Stealer.Banshee.7z" in item.metadata["files"]

        # Evidence table checks
        assert "### Primary Source Evidence" in item.content
        assert "**Indicators by role**" in item.content
        assert "T1555 (Credentials from Password Stores)" in item.content
        assert "T1005 (Data from Local System)" in item.content

        # Acknowledge and advance
        provider.acknowledge(item)
        item2 = provider.next_item()
        assert item2 is not None
        assert item2.identifier == "abcdef1234567890abcdef1234567890abcdef12"


def test_attack_technique_inference(tmp_path: Path) -> None:
    provider = VxUndergroundProvider(workspace=tmp_path)

    # Ransomware on Windows
    rw_techs = [t[0] for t in provider._infer_attack_techniques("Ransomware.LockBit", "Windows")]
    assert "T1486" in rw_techs
    assert "T1055" in rw_techs

    # Stealer on macOS
    st_techs = [t[0] for t in provider._infer_attack_techniques("Stealer.Banshee", "MacOS")]
    assert "T1555" in st_techs
    assert "T1204.002" in st_techs


def test_provider_factory(tmp_path: Path) -> None:
    settings = Settings(
        hecate_workspace=tmp_path,
        github_token="dummy_gh_token",
    )
    provider = get_provider("vxunderground", settings=settings)
    assert isinstance(provider, VxUndergroundProvider)
    assert provider.name == "vxunderground"
    assert provider.github_token == "dummy_gh_token"
