"""ANY.RUN Interactive Sandbox Detonation CTI Provider.

Ingests dynamic malware analysis and interactive execution telemetry from ANY.RUN.
Extracts process execution trees, living-off-the-land commands, Suricata alert tags,
dropped file hashes, and MITRE ATT&CK technique tags.

Supports both direct ANY.RUN API task polling (when ANYRUN_API_KEY is configured)
and the public ANY.RUN Threat Intelligence & Sandbox Execution Feed.
"""

from __future__ import annotations

import contextlib
import email.utils
import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class AnyRunError(RuntimeError):
    """Raised when an operation on the ANY.RUN provider fails."""


@dataclass
class AnyRunCursorState:
    """Track processed ANY.RUN analysis IDs or post GUIDs."""

    seen_ids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> AnyRunCursorState:
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_ids=list(raw.get("seen_ids") or []))
        except Exception as exc:
            log.warning("Failed to load ANY.RUN cursor from %s: %s; starting clean", path, exc)
            return cls()

    def advance(self, item_id: str) -> None:
        clean = item_id.strip()
        if clean and clean not in self.seen_ids:
            self.seen_ids.append(clean)
            if len(self.seen_ids) > 5000:
                self.seen_ids = self.seen_ids[-5000:]

    def already_seen(self, item_id: str) -> bool:
        return item_id.strip() in self.seen_ids

    def save(self, path: Path) -> None:
        payload = {
            "seen_ids": self.seen_ids,
            "last_updated": datetime.now(UTC).isoformat(),
        }
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


class AnyRunProvider(CTIProvider):
    """CTI provider consuming interactive detonation telemetry from ANY.RUN."""

    name: str = "anyrun"

    def __init__(
        self,
        cursor_file: Path,
        *,
        api_key: str | None = None,
        api_url: str = "https://api.any.run/v1/analysis",
        feed_url: str = "https://any.run/cybersecurity-blog/feed/",
        max_age_days: int = 90,
        request_timeout_sec: float = 25.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.feed_url = feed_url
        self.max_age_days = max_age_days
        self.request_timeout_sec = request_timeout_sec
        self._external_client = client is not None
        if client is not None:
            self._client = client
            if api_key and "Authorization" not in self._client.headers:
                self._client.headers["Authorization"] = f"API-Key {api_key}"
        else:
            self._client = httpx.Client(
                timeout=request_timeout_sec,
                headers={
                    "User-Agent": "Hecate-Runner/1.0",
                    "Accept": "application/json, application/xml, text/xml",
                    **({"Authorization": f"API-Key {api_key}"} if api_key else {}),
                },
                follow_redirects=True,
            )
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def poll(self) -> CTIItem | None:
        return self.next_item()

    def next_item(self) -> CTIItem | None:
        cursor = AnyRunCursorState.load(self.cursor_file)

        # Mode 1: Authenticated API query if API key is present
        if self.api_key:
            try:
                item = self._poll_api(cursor)
                if item:
                    return item
            except Exception as exc:
                log.warning("ANY.RUN API task poll failed: %s; falling back to public feed", exc)

        # Mode 2: Public sandbox threat analysis feed
        return self._poll_feed(cursor)

    def _poll_api(self, cursor: AnyRunCursorState) -> CTIItem | None:
        resp = self._client.get(f"{self.api_url}?limit=25")
        if resp.status_code == 429:
            log.warning("ANY.RUN API rate limit exceeded (HTTP 429)")
            return None
        resp.raise_for_status()
        data = resp.json().get("data", [])

        for task in data:
            task_id = str(task.get("task_id") or task.get("id") or "").strip()
            if not task_id or cursor.already_seen(task_id):
                continue

            threat_level = str(
                task.get("verdict") or task.get("threat_level") or "malicious"
            ).lower()
            if "malicious" not in threat_level and "suspicious" not in threat_level:
                continue

            title = f"ANY.RUN Detonation: {task.get('name') or task.get('tag') or task_id}"
            content = self._format_task_content(task)

            return CTIItem(
                content=content,
                source=self.name,
                received_at=datetime.now(UTC),
                identifier=f"anyrun-{task_id}",
                metadata={
                    "evidence_profile": "sandbox_execution",
                    "item_id": task_id,
                    "task_id": task_id,
                    "verdict": threat_level,
                },
                title=title,
                source_url=f"https://app.any.run/tasks/{task_id}",
            )
        return None

    def _poll_feed(self, cursor: AnyRunCursorState) -> CTIItem | None:
        try:
            resp = self._client.get(self.feed_url)
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
        except Exception as exc:
            log.warning("Failed to fetch ANY.RUN feed from %s: %s", self.feed_url, exc)
            return None

        channel = root.find("channel")
        if channel is None:
            return None

        cutoff = datetime.now(UTC) - timedelta(days=self.max_age_days)

        for item_node in channel.findall("item"):
            guid_node = item_node.find("guid")
            link_node = item_node.find("link")
            title_node = item_node.find("title")
            pub_node = item_node.find("pubDate")

            link = link_node.text.strip() if link_node is not None and link_node.text else ""
            item_id = (
                guid_node.text.strip() if guid_node is not None and guid_node.text else ""
            ) or link
            if not item_id or cursor.already_seen(item_id) or (link and cursor.already_seen(link)):
                continue

            pub_date = datetime.now(UTC)
            if pub_node is not None and pub_node.text:
                with contextlib.suppress(Exception):
                    pub_date = email.utils.parsedate_to_datetime(pub_node.text).astimezone(UTC)

            if pub_date < cutoff:
                continue

            raw_title = (
                title_node.text.strip()
                if title_node is not None and title_node.text
                else "ANY.RUN Analysis"
            )
            title = f"ANY.RUN Threat Intel: {raw_title}"

            desc_node = item_node.find("description")
            content_encoded = item_node.find("{http://purl.org/rss/1.0/modules/content/}encoded")
            summary = ""
            if content_encoded is not None and content_encoded.text:
                summary = re.sub(r"<[^>]+>", " ", content_encoded.text)
            elif desc_node is not None and desc_node.text:
                summary = re.sub(r"<[^>]+>", " ", desc_node.text)

            summary = re.sub(r"\s+", " ", summary).strip()
            content = self._format_feed_content(raw_title, link, pub_date, summary)

            return CTIItem(
                content=content,
                source=self.name,
                received_at=datetime.now(UTC),
                identifier=f"anyrun-{abs(hash(item_id)) % 10000000}",
                metadata={
                    "evidence_profile": "sandbox_execution",
                    "item_id": item_id,
                    "url": link,
                    "published_at": pub_date.isoformat(),
                },
                title=title,
                source_url=link,
            )

        return None

    def acknowledge(self, item: CTIItem) -> None:
        item_id = str(
            item.metadata.get("item_id")
            or item.metadata.get("task_id")
            or item.metadata.get("url")
            or item.identifier
        )
        if item_id:
            cursor = AnyRunCursorState.load(self.cursor_file)
            cursor.advance(item_id)
            if url := item.metadata.get("url"):
                cursor.advance(str(url))
            cursor.save(self.cursor_file)

    def _format_task_content(self, task: dict[str, Any]) -> str:
        task_id = str(task.get("task_id") or task.get("id") or "")
        tags = [str(t) for t in task.get("tags", [])]
        hashes = [str(h) for h in task.get("hashes", [])]
        techniques = _infer_techniques(" ".join(tags) + " " + str(task))

        lines = [
            f"Title: ANY.RUN Interactive Sandbox Detonation: {task.get('name') or task_id}",
            "Source: ANY.RUN Interactive Malware Hunting Sandbox",
            f"Task ID: {task_id}",
            f"Threat Classification: {task.get('verdict', 'malicious')}",
            f"Malware Family Tags: {', '.join(tags) if tags else 'Triage analysis'}",
            "",
            "Detonation Telemetry & Dynamic Behavior:",
            f"- Primary Sample Hash: {hashes[0] if hashes else 'N/A'}",
            f"- Environment: {task.get('os', 'Windows 10 64-bit')}",
            f"- Observed Network Beacons: {task.get('network_count', 0)} connections",
            "",
            "Execution Artifacts & Observed Command Lines:",
        ]
        for cmd in task.get("commands", [])[:8]:
            lines.append(f"  `{cmd}`")

        lines.extend(
            [
                "",
                f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}",
            ]
        )
        return "\n".join(lines)

    def _format_feed_content(self, title: str, link: str, pub_date: datetime, summary: str) -> str:
        techniques = _infer_techniques(title + " " + summary)
        hashes = _SHA256_RE.findall(summary)[:4]
        ips = [ip for ip in _IPV4_RE.findall(summary) if not ip.startswith("127.")][:4]

        lines = [
            f"Title: ANY.RUN Threat Analysis: {title}",
            "Source: ANY.RUN Interactive Threat Intelligence",
            f"Published Date: {pub_date.strftime('%Y-%m-%d')}",
            f"Report URL: {link}",
            "",
            "Detonation Overview & Threat Summary:",
            f"{summary[:1500]}",
            "",
            "Observed Telemetry & Indicators:",
            f"- Extracted Hashes: {', '.join(hashes) if hashes else 'Behavioral trace'}",
            f"- Network Endpoints: {', '.join(ips) if ips else 'Encrypted C2'}",
            "",
            f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}",
        ]
        return "\n".join(lines)


def _infer_techniques(text: str) -> list[str]:
    explicit = set(_TECHNIQUE_RE.findall(text))
    inferred: set[str] = set()

    lowered = text.lower()
    if any(k in lowered for k in ("powershell", "invoke-webrequest", "-enc", "-nop")):
        inferred.add("T1059.001")
    if any(k in lowered for k in ("cmd.exe", "batch", "whoami", "quser")):
        inferred.add("T1059.003")
    if any(k in lowered for k in ("vbs", "wscript", "cscript", "mshta")):
        inferred.add("T1059.005")
    if any(k in lowered for k in ("schtasks", "task scheduler", "at.exe")):
        inferred.add("T1053.005")
    if any(k in lowered for k in ("registry", "reg.exe", "currentversion\\run")):
        inferred.add("T1547.001")
    if any(k in lowered for k in ("c2", "beacon", "command-and-control", "connect back")):
        inferred.add("T1071.001")
    if any(k in lowered for k in ("injection", "process hollowing", "inject")):
        inferred.add("T1055")
    if any(k in lowered for k in ("stealer", "infostealer", "browser", "dpapi")):
        inferred.add("T1555.003")

    merged = sorted(explicit | inferred)
    return merged or ["T1059", "T1105", "T1071"]
