"""Durable, commit-pinned repository deltas. No fetched content is executed.

First poll establishes a baseline. Subsequent blob changes are queued durably;
acknowledging one item cannot consume the other changes in the commit. Tree
truncation, fetch/schema failures and rate limits retain the previous cursor.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider
from hecate_runner.integration_health import record_health


class GitHubDeltaProvider(CTIProvider):
    repo = ""
    branch = "main"
    prefix = ""
    suffixes: tuple[str, ...] = (".yml", ".yaml")

    def __init__(
        self,
        workspace: Path,
        *,
        github_token: str = "",
        client: httpx.Client | None = None,
        interval_seconds: int = 3600,
        **kwargs: Any,
    ):
        self.workspace = workspace
        self.cursor_file = workspace / ".cursors" / f"{self.name}_cursor.json"
        self.interval_seconds = interval_seconds
        self.client = client or httpx.Client(timeout=20, follow_redirects=True)
        self.owns_client = client is None
        self.headers = {"User-Agent": "Hecate-Runner/1.0", "Accept": "application/vnd.github+json"}
        if github_token:
            self.headers["Authorization"] = f"Bearer {github_token}"

    def close(self) -> None:
        if self.owns_client:
            self.client.close()

    def load(self) -> dict[str, Any]:
        if not self.cursor_file.exists():
            return {}
        # Never turn a corrupt cursor into a silent new baseline.
        state = json.loads(self.cursor_file.read_text())
        if not isinstance(state, dict):
            raise ValueError("invalid delta cursor")
        return state

    def save(self, state: dict[str, Any]) -> None:
        atomic_write_text(self.cursor_file, json.dumps(state))

    def get_json(self, path: str) -> Any:
        r = self.client.get("https://api.github.com/" + path, headers=self.headers)
        r.raise_for_status()
        return r.json()

    def fetch_entry(self, revision: str, path: str) -> tuple[str, Any]:
        # Credentials only go to api.github.com, not arbitrary content hosts.
        r = self.client.get(
            f"https://raw.githubusercontent.com/{self.repo}/{revision}/{quote(path, safe='/')}",
            headers={"User-Agent": "Hecate-Runner/1.0"},
        )
        r.raise_for_status()
        if len(r.content) > 2_000_000:
            raise ValueError("entry exceeds 2 MB")
        raw = r.text
        sections = re.split(r"(?m)^---[ \t]*\r?$", raw, maxsplit=2)
        raw_yaml = sections[1] if raw.startswith("---") and len(sections) == 3 else raw
        data = json.loads(raw) if path.endswith(".json") else yaml.safe_load(raw_yaml)
        if not isinstance(data, dict):
            raise ValueError("entry is not an object")
        return raw, data

    def relevant(self, path: str) -> bool:
        return path.startswith(self.prefix) and path.endswith(self.suffixes)

    def refresh(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("pending") or time.time() - state.get("checked", 0) < self.interval_seconds:
            return state
        head = self.get_json(f"repos/{self.repo}/commits/{self.branch}")
        revision = head["sha"]
        if not re.fullmatch("[a-f0-9]{40}", revision):
            raise ValueError("invalid revision")
        if revision == state.get("revision"):
            state["checked"] = time.time()
            self.save(state)
            record_health(self.workspace, self.name, True, "commit unchanged")
            return state
        tree = self.get_json(f"repos/{self.repo}/git/trees/{revision}?recursive=1")
        if tree.get("truncated"):
            raise ValueError("GitHub tree truncated; cursor retained")
        entries = {
            v["path"]: v["sha"]
            for v in tree["tree"]
            if v.get("type") == "blob" and self.relevant(v["path"])
        }
        if not entries:
            raise ValueError("no entries match expected repository schema")
        if not state.get("revision"):
            state = {
                "revision": revision,
                "entries": entries,
                "pending": [],
                "checked": time.time(),
            }
        else:
            pending = [
                {"path": p, "blob": sha}
                for p, sha in sorted(entries.items())
                if state.get("entries", {}).get(p) != sha
            ]
            state.update(
                pending=pending, next_revision=revision, next_entries=entries, checked=time.time()
            )
            if not pending:
                state.update(revision=revision, entries=entries)
                state.pop("next_entries", None)
                state.pop("next_revision", None)
        self.save(state)
        record_health(
            self.workspace, self.name, True, f"{len(entries)} entries; baseline/delta checked"
        )
        return state

    def next_item(self) -> CTIItem | None:
        try:
            state = self.refresh(self.load())
            for _ in range(10):
                if not state.get("pending"):
                    break
                change = state["pending"][0]
                raw, data = self.fetch_entry(state["next_revision"], change["path"])
                item = self.build_item(data, raw, change["path"], state["next_revision"])
                if item is not None:
                    item.metadata.update(delta_path=change["path"], delta_blob=change["blob"])
                    record_health(self.workspace, self.name, True, "changed entry parsed")
                    return item
                # An intentional schema/risk filter consumes only that rejected entry.
                self.consume(state, change["path"], change["blob"])
            return None
        except (httpx.HTTPError, ValueError, KeyError, TypeError, yaml.YAMLError):
            record_health(self.workspace, self.name, False, "fetch/schema failure; cursor retained")
            raise

    def consume(self, state: dict[str, Any], path: str, blob: str) -> None:
        state["pending"] = [
            p for p in state.get("pending", []) if (p["path"], p["blob"]) != (path, blob)
        ]
        if not state["pending"] and "next_revision" in state:
            state.update(revision=state.pop("next_revision"), entries=state.pop("next_entries"))
        self.save(state)

    def acknowledge(self, item: CTIItem) -> None:
        self.consume(self.load(), item.metadata["delta_path"], item.metadata["delta_blob"])

    def reject(self, path: str, revision: str, reason: str) -> None:
        """Retain bounded intake decisions so intentional filters are explainable."""
        destination = self.workspace / ".hecate" / "source-decisions" / f"{self.name}.json"
        decisions = json.loads(destination.read_text()) if destination.exists() else []
        decisions.append(
            {
                "path": path,
                "revision": revision,
                "reason": reason,
                "checked_at": datetime.now(UTC).isoformat(),
            }
        )
        atomic_write_text(destination, json.dumps(decisions[-200:]))

    def build_item(
        self, data: dict[str, Any], raw: str, path: str, revision: str
    ) -> CTIItem | None:
        raise NotImplementedError

    def item(self, title: str, text: str, path: str, revision: str, **metadata: Any) -> CTIItem:
        url = f"https://github.com/{self.repo}/blob/{revision}/{quote(path, safe='/')}"
        return CTIItem(
            title=title,
            content=f"Title: {title}\nSource: {self.name}\nURL: {url}\n\n{text}",
            source=self.name,
            source_url=url,
            identifier=f"{self.name}:{revision}:{path}",
            received_at=datetime.now(UTC),
            metadata={
                "processing_track": "deep",
                "source_revision": revision,
                "evidence_profile": "structured_reference",
                **metadata,
            },
        )
