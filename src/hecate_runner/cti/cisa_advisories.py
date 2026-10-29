"""Dedicated CISA narrative and ICS intake with official CSAF fallback."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

import feedparser

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.github_delta import GitHubDeltaProvider
from hecate_runner.integration_health import record_health

BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"


class CisaAdvisoryProvider(GitHubDeltaProvider):
    name = "cisa_advisories"
    repo = "cisagov/CSAF"
    branch = "develop"
    prefix = "csaf_files/IT/"
    suffixes = (".json",)

    def next_item(self) -> CTIItem | None:
        # The feed is dedicated, uses a browser UA, and has an independent
        # durable cursor. A 403 is a failed channel, never an empty success.
        import httpx

        feed_cursor = self.workspace / ".cursors" / "cisa_narrative_feed.json"
        state = json.loads(feed_cursor.read_text()) if feed_cursor.exists() else {}
        try:
            if time.time() - state.get("checked", 0) < self.interval_seconds and not state.get(
                "pending"
            ):
                return super().next_item()
            if not state.get("pending"):
                r = self.client.get(
                    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
                    headers={"User-Agent": BROWSER_UA},
                )
                r.raise_for_status()
                feed = feedparser.parse(r.text)
                entries = [
                    dict(e)
                    for e in feed.entries
                    if str(e.get("link", "")).startswith("https://www.cisa.gov/")
                ]
                if not entries:
                    raise ValueError("CISA feed returned no valid advisory entries")
                for entry in entries:
                    entry["_hecate_id"] = (
                        entry["link"]
                        + ":"
                        + str(entry.get("updated") or entry.get("published") or "")
                    )
                baseline = "seen" not in state
                seen = state.get("seen", [])
                state.update(
                    checked=time.time(),
                    seen=seen,
                    pending=[] if baseline else [e for e in entries if e["_hecate_id"] not in seen],
                )
                if baseline:
                    state["seen"] = [e["_hecate_id"] for e in entries]
                atomic_write_text(feed_cursor, json.dumps(state))
                record_health(
                    self.workspace,
                    "cisa_narrative",
                    True,
                    "official advisory feed schema confirmed",
                )
            if state.get("pending"):
                entry = state["pending"][0]
                r = self.client.get(entry["link"], headers={"User-Agent": BROWSER_UA})
                r.raise_for_status()
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(r.text, "html.parser")
                main = soup.find("main") or soup
                text = main.get_text(" ", strip=True)
                if len(text) < 200:
                    raise ValueError("empty CISA advisory body")
                record_health(
                    self.workspace, self.name, True, "official narrative advisory fetched"
                )
                return CTIItem(
                    content=f"Title: {entry.get('title', 'CISA advisory')}\nSource: CISA\n\n{text}",
                    source=self.name,
                    source_url=entry["link"],
                    identifier=entry["_hecate_id"],
                    title=str(entry.get("title", "CISA advisory")),
                    received_at=datetime.now(UTC),
                    metadata={
                        "processing_track": "deep",
                        "evidence_profile": "narrative_advisory",
                        "cisa_feed": True,
                    },
                )
        except (httpx.HTTPError, ValueError):
            record_health(
                self.workspace, "cisa_narrative", False, "narrative channel fetch/schema failure"
            )
        return super().next_item()

    def acknowledge(self, item: CTIItem) -> None:
        if not item.metadata.get("cisa_feed"):
            return super().acknowledge(item)
        cursor = self.workspace / ".cursors" / "cisa_narrative_feed.json"
        state = json.loads(cursor.read_text())
        state["seen"] = list(dict.fromkeys([*state.get("seen", []), item.identifier]))[-1000:]
        state["pending"] = [
            e for e in state.get("pending", []) if e["_hecate_id"] != item.identifier
        ]
        atomic_write_text(cursor, json.dumps(state))

    def build_item(self, data: dict[str, Any], raw: str, path: str, revision: str) -> CTIItem:
        doc = data["document"]
        if doc.get("publisher", {}).get("name") != "CISA" or not doc.get("tracking", {}).get("id"):
            raise ValueError("not a CISA CSAF advisory")
        notes = "\n".join(str(n.get("text", "")) for n in doc.get("notes", []))
        cves = [v["cve"] for v in data.get("vulnerabilities", []) if v.get("cve")]
        tlp = doc.get("distribution", {}).get("tlp", {}).get("label")
        tlp = "CLEAR" if tlp == "WHITE" else tlp
        title = f"CISA {doc['tracking']['id']}: {doc['title']}"
        return self.item(
            title,
            f"Official CISA structured advisory; vulnerability impact statements are capabilities, "
            f"not proof of exploitation. TLP:{tlp or 'UNKNOWN'}\n{notes}\nVerbatim CSAF document:\n{raw}",
            path,
            revision,
            evidence_profile="vulnerability_advisory",
            cves=cves,
            advisory_id=doc["tracking"]["id"],
            advisory_version=doc["tracking"].get("version"),
            tlp=tlp,
            structured_document=data,
            is_ics=self.name == "cisa_ics",
        )


class CisaICSProvider(CisaAdvisoryProvider):
    name = "cisa_ics"
    prefix = "csaf_files/OT/"

    def next_item(self) -> CTIItem | None:
        return GitHubDeltaProvider.next_item(self)
