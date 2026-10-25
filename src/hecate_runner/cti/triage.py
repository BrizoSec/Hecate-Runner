"""Hatching Triage (tria.ge) dynamic sandbox CTI provider.

Queries the Tria.ge sandbox API (https://api.tria.ge/v0) to ingest recent dynamic
malware detonations, extracted C2 configurations, process trees, dropped tools,
and behavioral MITRE ATT&CK techniques observed in the sandbox execution environment.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class TriageError(RuntimeError):
    """Raised when an operation on the Tria.ge provider fails."""


@dataclass
class TriageCursorState:
    """Track processed Tria.ge sample IDs to prevent duplicate processing."""

    seen_ids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> TriageCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_ids=list(data.get("seen_ids", [])))
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            log.warning("Tria.ge cursor %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(path, json.dumps({"seen_ids": self.seen_ids[-1000:]}, indent=2))

    def already_seen(self, sample_id: str) -> bool:
        return sample_id in self.seen_ids

    def advance(self, sample_id: str) -> None:
        if sample_id and sample_id not in self.seen_ids:
            self.seen_ids.append(sample_id)


class TriageProvider(CTIProvider):
    """CTI provider consuming dynamic malware detonation traces from Hatching Triage."""

    name: str = "triage"

    def __init__(
        self,
        cursor_file: Path,
        api_key: str | None = None,
        base_url: str = "https://api.tria.ge/v0",
        search_query: str = "tag:malware",
        request_timeout_sec: float = 20.0,
        client: httpx.Client | None = None,
    ):
        self.cursor_file = cursor_file
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.search_query = search_query
        self.request_timeout_sec = request_timeout_sec
        if client is not None:
            self._client = client
            if api_key and "Authorization" not in self._client.headers:
                self._client.headers["Authorization"] = f"Bearer {api_key}"
        else:
            self._client = httpx.Client(
                timeout=request_timeout_sec,
                headers={
                    "User-Agent": "Hecate-Runner/1.0",
                    "Accept": "application/json",
                    **({"Authorization": f"Bearer {api_key}"} if api_key else {}),
                },
                follow_redirects=True,
            )
        self._owns_client = client is None
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def next_item(self) -> CTIItem | None:
        if not self.api_key:
            log.debug("Tria.ge provider skipped: TRIAGE_API_KEY is not configured")
            return None

        cursor = TriageCursorState.load(self.cursor_file)
        try:
            samples = self._fetch_recent_samples()
        except TriageError as exc:
            log.warning("Failed to search Tria.ge sandbox: %s", exc)
            return None

        for sample in samples:
            sample_id = str(sample.get("id") or "").strip()
            if not sample_id or cursor.already_seen(sample_id):
                continue

            try:
                overview = self._fetch_overview(sample_id)
            except TriageError as exc:
                log.warning("Failed to fetch Tria.ge sample %s overview: %s", sample_id, exc)
                continue

            return self._sample_to_cti_item(sample_id, sample, overview)

        log.debug("No new unrouted dynamic detonations found on Tria.ge")
        return None

    def acknowledge(self, item: CTIItem) -> None:
        sample_id = item.metadata.get("sample_id") or item.identifier
        if not sample_id:
            log.warning("Cannot acknowledge Tria.ge item without sample_id (%r)", item)
            return
        cursor = TriageCursorState.load(self.cursor_file)
        cursor.advance(str(sample_id))
        cursor.save(self.cursor_file)

    def _fetch_recent_samples(self) -> list[dict[str, Any]]:
        url = f"{self.base_url}/search?query={self.search_query}&limit=20"
        try:
            resp = self._client.get(url)
        except httpx.RequestError as exc:
            raise TriageError(f"HTTP request to {url} failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise TriageError(
                f"Authentication failure (HTTP {resp.status_code}); check TRIAGE_API_KEY"
            )
        if resp.status_code == 429:
            raise TriageError("Tria.ge rate limit reached (HTTP 429)")
        if resp.status_code != 200:
            raise TriageError(f"HTTP {resp.status_code} from {url}")

        data = resp.json()
        return list(data.get("data") or [])

    def _fetch_overview(self, sample_id: str) -> dict[str, Any]:
        url = f"{self.base_url}/samples/{sample_id}/overview.json"
        try:
            resp = self._client.get(url)
        except httpx.RequestError as exc:
            raise TriageError(f"HTTP request to {url} failed: {exc}") from exc

        if resp.status_code != 200:
            raise TriageError(f"HTTP {resp.status_code} fetching overview for sample {sample_id}")

        return dict(resp.json())

    def _sample_to_cti_item(
        self, sample_id: str, sample: dict[str, Any], overview: dict[str, Any]
    ) -> CTIItem:
        analysis = overview.get("analysis") or {}
        sample_info = overview.get("sample") or {}
        extracted_cfgs = overview.get("extracted") or []

        score = analysis.get("score")
        if score is None:
            score = sample_info.get("score", 0)

        # Families & tags
        families_raw = analysis.get("family") or []
        families = [families_raw] if isinstance(families_raw, str) else list(families_raw)
        tags_raw = analysis.get("tags") or []
        tags = [tags_raw] if isinstance(tags_raw, str) else list(tags_raw)

        # Target platform
        target = str(sample_info.get("target") or analysis.get("platform") or "unknown")
        filename = str(sample_info.get("filename") or sample.get("filename") or "sample.bin")
        sha256 = str(sample_info.get("sha256") or sample.get("sha256") or "")
        md5 = str(sample_info.get("md5") or sample.get("md5") or "")

        # Extract C2s, botnets, and mutexes from static/dynamic configs
        c2_list: list[str] = []
        botnets: list[str] = []
        mutexes: list[str] = []
        for item in extracted_cfgs:
            if not isinstance(item, dict):
                continue
            cfg = item.get("config")
            if not isinstance(cfg, dict):
                continue
            f_name = cfg.get("family")
            if f_name and str(f_name) not in families:
                families.append(str(f_name))
            raw_c2 = cfg.get("c2") or cfg.get("c2_urls") or cfg.get("urls") or []
            if isinstance(raw_c2, str):
                raw_c2 = [raw_c2]
            for c in raw_c2:
                c_clean = str(c).strip()
                if c_clean and c_clean not in c2_list:
                    c2_list.append(c_clean)
            bot_id = cfg.get("botnet") or cfg.get("bot_id") or cfg.get("campaign")
            if bot_id and str(bot_id) not in botnets:
                botnets.append(str(bot_id))
            mutex = cfg.get("mutex")
            if mutex and str(mutex) not in mutexes:
                mutexes.append(str(mutex))

        # Extract dynamic execution command lines and MITRE techniques from signatures
        signatures = overview.get("signatures") or []
        cmd_lines: list[str] = []
        techniques: list[str] = []
        for sig in signatures:
            if not isinstance(sig, dict):
                continue
            ttp = sig.get("ttp") or sig.get("attck") or ""
            if isinstance(ttp, str):
                for match in _TECHNIQUE_RE.findall(ttp):
                    if match not in techniques:
                        techniques.append(match)
            elif isinstance(ttp, list):
                for t in ttp:
                    for match in _TECHNIQUE_RE.findall(str(t)):
                        if match not in techniques:
                            techniques.append(match)

            desc = str(sig.get("desc") or sig.get("name") or "")
            for match in _TECHNIQUE_RE.findall(desc):
                if match not in techniques:
                    techniques.append(match)

            # Check marks / indicators in signature
            marks = sig.get("marks") or []
            for mark in marks:
                if isinstance(mark, dict):
                    cmd = mark.get("command_line") or mark.get("cmd") or mark.get("call")
                    if cmd and str(cmd) not in cmd_lines:
                        cmd_lines.append(str(cmd))

        # Extract network connections from overview
        targets = overview.get("targets") or []
        net_ips: list[str] = []
        net_domains: list[str] = []
        for t in targets:
            if isinstance(t, dict):
                for ip in t.get("iocs", {}).get("ips", []):
                    if ip not in net_ips and not str(ip).startswith(("127.", "0.", "255.")):
                        net_ips.append(str(ip))
                for dom in t.get("iocs", {}).get("domains", []):
                    if dom not in net_domains and not str(dom).endswith((".tria.ge", ".local")):
                        net_domains.append(str(dom))

        family_str = ", ".join(families) if families else "Unclassified Threat"
        title = f"Tria.ge Dynamic Detonation: {family_str} ({filename})"
        link = f"https://tria.ge/{sample_id}"

        # Build prompt blurb
        lines = [
            f"Tria.ge Dynamic Detonation: {family_str}",
            "Source: Hatching Triage Sandbox",
            f"Link: {link}",
            f"Platform: {target}",
            f"Threat Score: {score}/10",
        ]
        if tags:
            lines.append(f"Tags: {', '.join(tags[:8])}")
        if techniques:
            lines.append(f"{ATTACK_TECHNIQUE_LINE} {', '.join(sorted(techniques))}")

        if cmd_lines:
            lines.append("\nExtracted Process Executions & Command Lines:")
            for cmd in cmd_lines[:8]:
                lines.append(f"  - `{cmd}`")

        c2_summary = []
        if c2_list:
            c2_summary.append(f"C2 Endpoints: {', '.join(c2_list[:4])}")
        if net_domains:
            c2_summary.append(f"Contacted Domains: {', '.join(net_domains[:4])}")
        if net_ips:
            c2_summary.append(f"Contacted IPs: {', '.join(net_ips[:4])}")
        if c2_summary:
            lines.append(f"\nNetwork Infrastructure & C2:\n  {'; '.join(c2_summary)}")

        if mutexes or botnets:
            meta_items = []
            if mutexes:
                meta_items.append(f"Mutex: {', '.join(mutexes[:2])}")
            if botnets:
                meta_items.append(f"Campaign: {', '.join(botnets[:2])}")
            lines.append(f"\nPersistence & Botnet Markers: {'; '.join(meta_items)}")

        lines.append(f"\nSample Attributes:\n  SHA256: {sha256}\n  Filename: {filename}")

        content = "\n".join(lines)

        indicators: dict[str, list[str]] = {}
        if sha256:
            indicators["sha256"] = [sha256]
        if md5:
            indicators["md5"] = [md5]
        if net_ips:
            indicators["ipv4"] = net_ips[:15]
        if net_domains:
            indicators["domain"] = net_domains[:15]

        metadata = {
            "sample_id": sample_id,
            "filename": filename,
            "sha256": sha256,
            "family": family_str,
            "score": score,
            "platform": target,
            "techniques": sorted(techniques),
            "indicators": indicators,
            "c2_urls": c2_list,
            "evidence_profile": "sandbox_detonation",
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=datetime.now(UTC),
            identifier=sample_id,
            metadata=metadata,
            title=title,
            source_url=link,
        )
