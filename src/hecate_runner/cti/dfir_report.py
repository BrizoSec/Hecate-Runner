"""The DFIR Report structured CTI provider.

Consumes in-depth intrusion walkthroughs from The DFIR Report (https://thedfirreport.com),
extracting structured procedural commands, attack phases, MITRE ATT&CK techniques,
and forensic artifacts (dropped tools, registry modifications, C2 endpoints) to ground
high-confidence detection engineering and purple team replay.
"""

from __future__ import annotations

import html
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import feedparser
import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider, extract_article_text

log = logging.getLogger(__name__)

REQUEST_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|xyz|top|online|site|club|biz|info)\b",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_REG_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\\\-]+\b", re.IGNORECASE
)
_PATH_RE = re.compile(
    r"[a-zA-Z]:\\(?:[A-Za-z0-9_.\-\s]+\\)+[A-Za-z0-9_.\-\s]+\.(?:exe|dll|bat|ps1|vbs|hta|bin|dat|zip|7z|rar)",
    re.IGNORECASE,
)

_COMMAND_PATTERNS = (
    re.compile(r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+[^\n\r]+", re.IGNORECASE),
    re.compile(
        r"(?:cmd(?:\.exe)?\s+/c|net(?:\.exe)?\s+(?:user|group|localgroup|view|use)|nltest(?:\.exe)?|whoami(?:\.exe)?|wmic(?:\.exe)?|reg(?:\.exe)?\s+(?:add|query|delete)|certutil(?:\.exe)?|vssadmin(?:\.exe)?|wevtutil(?:\.exe)?|schtasks(?:\.exe)?|sc(?:\.exe)?\s+(?:create|start|config)|rundll32(?:\.exe)?|msbuild(?:\.exe)?|installutil(?:\.exe)?|regsvr32(?:\.exe)?)\s+[^\n\r]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:adfind(?:\.exe)?|rclone(?:\.exe)?|chisel(?:\.exe)?|mimikatz(?:\.exe)?|impacket|procdump(?:\.exe)?|sharpsecdump(?:\.exe)?|seatbelt(?:\.exe)?)\s+[^\n\r]+",
        re.IGNORECASE,
    ),
)


class DfirReportError(RuntimeError):
    """Raised when an operation on The DFIR Report provider fails."""


@dataclass
class DfirReportCursorState:
    """Track processed DFIR Report entry identifiers to prevent duplication."""

    seen_ids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> DfirReportCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_ids=list(data.get("seen_ids", [])))
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            log.warning("DFIR Report cursor %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps({"seen_ids": self.seen_ids[-500:]}, indent=2))

    def already_seen(self, identifiers: Iterable[str]) -> bool:
        seen = set(self.seen_ids)
        return any(ident in seen for ident in identifiers if ident)

    def advance(self, identifiers: Iterable[str]) -> None:
        for ident in identifiers:
            if ident and ident not in self.seen_ids:
                self.seen_ids.append(ident)


def extract_procedural_artifacts(text: str) -> dict[str, list[str]]:
    """Extract procedural execution commands, hashes, paths, registry keys, and network IOCs."""
    clean = html.unescape(_HTML_TAG_RE.sub(" ", text or ""))

    commands: list[str] = []
    for pattern in _COMMAND_PATTERNS:
        for match in pattern.findall(clean):
            cmd = match.strip().strip("`'\"")
            if cmd and len(cmd) > 5 and cmd not in commands:
                commands.append(cmd)

    files = list(dict.fromkeys(_PATH_RE.findall(clean)))
    reg_keys = list(dict.fromkeys(_REG_RE.findall(clean)))
    ips = [
        ip
        for ip in dict.fromkeys(_IPV4_RE.findall(clean))
        if not ip.startswith(("127.", "0.", "255."))
    ]
    domains = [
        d.lower()
        for d in dict.fromkeys(_DOMAIN_RE.findall(clean))
        if not d.lower().endswith(
            (".thedfirreport.com", ".wordpress.com", ".github.com", ".microsoft.com", ".google.com")
        )
    ]
    sha256s = list(dict.fromkeys(_SHA256_RE.findall(clean)))
    md5s = list(dict.fromkeys(_MD5_RE.findall(clean)))

    return {
        "commands": commands[:15],
        "file_paths": files[:15],
        "registry_keys": reg_keys[:10],
        "ipv4": ips[:20],
        "domains": domains[:20],
        "sha256": sha256s[:20],
        "md5": md5s[:20],
    }


class DfirReportProvider(CTIProvider):
    """CTI provider consuming full intrusion reports from The DFIR Report."""

    name: str = "dfir_report"

    def __init__(
        self,
        cursor_file: Path,
        feed_url: str = "https://thedfirreport.com/feed/",
        max_entry_age_days: int = 90,
        request_timeout_sec: float = 30.0,
        client: httpx.Client | None = None,
    ):
        self.feed_url = feed_url
        self.cursor_file = cursor_file
        self.max_entry_age_days = max_entry_age_days
        self.request_timeout_sec = request_timeout_sec
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={"User-Agent": REQUEST_USER_AGENT},
            follow_redirects=True,
        )
        self._owns_client = client is None
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def next_item(self) -> CTIItem | None:
        cursor = DfirReportCursorState.load(self.cursor_file)
        cutoff = datetime.now(UTC) - timedelta(days=self.max_entry_age_days)

        try:
            entries = self._fetch_entries()
        except DfirReportError as exc:
            log.warning("Failed to fetch DFIR Report entries: %s", exc)
            return None

        candidates: list[dict[str, Any]] = []
        for entry in entries:
            identifiers = self._entry_identifiers(entry)
            if not identifiers or cursor.already_seen(identifiers):
                continue
            published = self._entry_published(entry)
            if published is not None and published < cutoff:
                continue
            candidates.append(entry)

        if not candidates:
            log.debug("No new entries found in The DFIR Report feed")
            return None

        # Process oldest unrouted entry first
        candidates.sort(key=lambda e: self._entry_published(e) or datetime.max.replace(tzinfo=UTC))
        entry = candidates[0]
        return self._entry_to_cti_item(entry)

    def acknowledge(self, item: CTIItem) -> None:
        identifiers = [
            val for val in (item.metadata.get("entry_id"), item.metadata.get("entry_link")) if val
        ]
        if not identifiers:
            log.warning("Cannot acknowledge DFIR Report item without entry identifiers (%r)", item)
            return
        cursor = DfirReportCursorState.load(self.cursor_file)
        cursor.advance(identifiers)
        cursor.save(self.cursor_file)

    def _fetch_entries(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self.feed_url)
        except httpx.RequestError as exc:
            raise DfirReportError(f"HTTP request to {self.feed_url} failed: {exc}") from exc

        if resp.status_code != 200:
            raise DfirReportError(f"HTTP {resp.status_code} from {self.feed_url}")

        parsed = feedparser.parse(resp.content)
        if parsed.bozo and not parsed.entries:
            raise DfirReportError(
                f"Unparseable feed from {self.feed_url}: {parsed.get('bozo_exception', 'unknown error')}"
            )

        return list(parsed.entries)

    def _entry_identifiers(self, entry: dict[str, Any]) -> list[str]:
        ids: list[str] = []
        for k in ("id", "link", "guid"):
            v = str(entry.get(k) or "").strip()
            if v and v not in ids:
                ids.append(v)
        return ids

    def _entry_published(self, entry: dict[str, Any]) -> datetime | None:
        parsed_time = entry.get("published_parsed") or entry.get("updated_parsed")
        if parsed_time:
            try:
                return datetime(
                    parsed_time[0],
                    parsed_time[1],
                    parsed_time[2],
                    parsed_time[3],
                    parsed_time[4],
                    parsed_time[5],
                    tzinfo=UTC,
                )
            except (TypeError, ValueError, IndexError):
                pass
        return None

    def _entry_to_cti_item(self, entry: dict[str, Any]) -> CTIItem:
        title = html.unescape(str(entry.get("title") or "Untitled DFIR Intrusion Report")).strip()
        link = str(entry.get("link") or "").strip()
        published = self._entry_published(entry) or datetime.now(UTC)
        entry_id = str(entry.get("id") or link)
        tags = [t.get("term", "") for t in entry.get("tags", []) if t.get("term")]

        # Read content from feed or extract via article scraper
        feed_content = ""
        content_list = entry.get("content") or []
        if isinstance(content_list, list) and content_list:
            feed_content = str(content_list[0].get("value", ""))
        if not feed_content:
            feed_content = str(entry.get("summary") or "")

        extracted_prose = extract_article_text(link) if link else ""
        combined_text = f"{feed_content}\n\n{extracted_prose}" if extracted_prose else feed_content

        # Extract procedural artifacts
        artifacts = extract_procedural_artifacts(combined_text)
        techniques = sorted(set(_TECHNIQUE_RE.findall(combined_text)))

        # Format blurb
        lines = [
            f"DFIR Report: {title}",
            "Source: The DFIR Report",
            f"Link: {link}",
        ]
        if tags:
            lines.append(f"Tags: {', '.join(tags[:10])}")
        if techniques:
            lines.append(f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}")

        if artifacts["commands"]:
            lines.append("\nIntrusion Execution Procedures & Commands:")
            for cmd in artifacts["commands"][:10]:
                lines.append(f"  - `{cmd}`")

        if artifacts["file_paths"]:
            lines.append("\nDropped Files & Tool Paths:")
            for p in artifacts["file_paths"][:8]:
                lines.append(f"  - `{p}`")

        if artifacts["registry_keys"]:
            lines.append("\nRegistry Modifications:")
            for r in artifacts["registry_keys"][:6]:
                lines.append(f"  - `{r}`")

        ioc_summary = []
        if artifacts["ipv4"]:
            ioc_summary.append(f"IPs: {', '.join(artifacts['ipv4'][:6])}")
        if artifacts["domains"]:
            ioc_summary.append(f"Domains: {', '.join(artifacts['domains'][:6])}")
        if artifacts["sha256"]:
            ioc_summary.append(f"Hashes: {', '.join(artifacts['sha256'][:4])}")
        if ioc_summary:
            lines.append(f"\nObservable IOCs:\n  {'; '.join(ioc_summary)}")

        # Clean narrative text
        clean_narrative = html.unescape(
            _HTML_TAG_RE.sub(" ", feed_content or extracted_prose)
        ).strip()
        if clean_narrative:
            summary = re.sub(r"\s+", " ", clean_narrative)[:2000]
            lines.append(f"\nCase Summary & Analysis:\n{summary}")

        content = "\n".join(lines)

        indicators: dict[str, list[str]] = {}
        if artifacts["ipv4"]:
            indicators["ipv4"] = artifacts["ipv4"]
        if artifacts["domains"]:
            indicators["domain"] = artifacts["domains"]
        if artifacts["sha256"]:
            indicators["sha256"] = artifacts["sha256"]
        if artifacts["md5"]:
            indicators["md5"] = artifacts["md5"]

        metadata = {
            "entry_id": entry_id,
            "entry_link": link,
            "entry_title": title,
            "entry_tags": tags,
            "techniques": techniques,
            "indicators": indicators,
            "procedural_commands": artifacts["commands"],
            "evidence_profile": "intrusion_walkthrough",
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=published,
            identifier=entry_id,
            metadata=metadata,
            title=title,
            source_url=link,
        )
