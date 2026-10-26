from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

# Official apex domains for common brands to exclude legitimate certificates from alerting
OFFICIAL_BRAND_DOMAINS: set[str] = {
    "apple.com",
    "icloud.com",
    "apple-cloudkit.com",
    "notion.so",
    "notion.site",
    "google.com",
    "gmail.com",
    "googleapis.com",
    "googleusercontent.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "azure.com",
    "windows.net",
    "office365.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "binance.com",
    "binance.org",
    "metamask.io",
    "trezor.io",
    "ledger.com",
    "paypal.com",
    "coinbase.com",
    "phantom.app",
}


@dataclass
class CertStreamCursorState:
    seen_domains: list[str] = field(default_factory=list)
    max_history: int = 5000

    def to_json(self) -> str:
        return json.dumps({"seen_domains": self.seen_domains[-self.max_history :]})

    @classmethod
    def from_file(cls, path: Path) -> CertStreamCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            seen = data.get("seen_domains", [])
            if isinstance(seen, list):
                return cls(seen_domains=seen)
            return cls()
        except (OSError, ValueError):
            return cls()

    def record_domain(self, domain: str, path: Path) -> None:
        clean = domain.strip().lower()
        if clean and clean not in self.seen_domains:
            self.seen_domains.append(clean)
            if len(self.seen_domains) > self.max_history:
                self.seen_domains = self.seen_domains[-self.max_history :]
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(path, self.to_json())
            except Exception as e:
                log.warning("Failed to save CertStream cursor state: %s", e)


class CertStreamProvider(CTIProvider):
    """Real-time Certificate Transparency log streaming provider via CertStream.

    Monitors incoming TLS certificate issuances in real-time, matching domain names
    against high-value target brand names and suspicious staging/ClickFix lure keywords.
    """

    name = "certstream"

    def __init__(
        self,
        cursor_file: Path,
        stream_url: str = "wss://certstream.calidog.io/",
        brand_patterns: list[str] | None = None,
        suspicious_keywords: list[str] | None = None,
        poll_timeout_sec: float = 5.0,
        max_buffer_size: int = 100,
        buffer_file: Path | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.buffer_file = buffer_file or (cursor_file.parent / "certstream_buffer.json")
        self.stream_url = stream_url
        self.brand_patterns = [b.lower() for b in (brand_patterns or []) if b]
        self.suspicious_keywords = [k.lower() for k in (suspicious_keywords or []) if k]
        self.poll_timeout_sec = poll_timeout_sec
        self.max_buffer_size = max_buffer_size
        self._items: list[CTIItem] = []
        self._cursor = CertStreamCursorState.from_file(self.cursor_file)

    def matches_brand_protection(self, domain: str) -> tuple[bool, str, list[str]]:
        """Evaluate if domain matches brand protection and suspicious staging keywords."""
        clean = domain.strip().lower()
        if clean.startswith("*."):
            clean = clean[2:]

        # Skip official brand apex domains and their legitimate subdomains
        for official in OFFICIAL_BRAND_DOMAINS:
            if clean == official or clean.endswith(f".{official}"):
                return False, "", []

        # Find matching brands
        matched_brand = ""
        for brand in self.brand_patterns:
            # Word boundary or hyphenated brand match (e.g., "notion-app", "apple-id")
            pattern = rf"(^|[.\-_]){re.escape(brand)}([.\-_]|$)"
            if re.search(pattern, clean):
                matched_brand = brand
                break

        if not matched_brand:
            return False, "", []

        # Find matching suspicious staging keywords
        matched_keywords: list[str] = []
        for kw in self.suspicious_keywords:
            kw_pattern = rf"(^|[.\-_]){re.escape(kw)}([.\-_]|$)"
            if re.search(kw_pattern, clean):
                matched_keywords.append(kw)

        # Flag if domain contains brand AND at least one suspicious staging keyword
        if matched_keywords:
            return True, matched_brand, matched_keywords

        return False, "", []

    def _create_item(
        self,
        domain: str,
        brand: str,
        keywords: list[str],
        issuer: str = "Unknown CA",
        all_domains: list[str] | None = None,
    ) -> CTIItem:
        clean = domain.strip().lower()
        if clean.startswith("*."):
            clean = clean[2:]
        domains = all_domains or [clean]
        blurb_lines = [
            "CertStream Alert: Potential Brand Impersonation / Staging Domain",
            "Indicators (1 total): domain (1)\n",
            f"Domain: {clean}",
            f"Subject Alternative Names: {', '.join(str(s) for s in domains[:5])}",
            f"Issuer: {issuer}",
            f"Target Brand Match: {brand}",
            f"Matched Staging Patterns: {', '.join(keywords)}",
            "Threat Context: Newly issued SSL certificate matches high-value target brand and suspicious staging keywords, indicating adversary infrastructure staging or ClickFix lure setup.",
            f"Certificate Transparency Query: https://crt.sh/?q={clean}",
        ]
        content = "\n".join(blurb_lines)
        return CTIItem(
            content=content,
            source=self.name,
            identifier=f"certstream-{clean}",
            title=f"Suspicious Certificate Staged: {clean}",
            source_url=f"https://crt.sh/?q={clean}",
            metadata={
                "domain": clean,
                "all_domains": domains,
                "issuer": issuer,
                "matched_brand": brand,
                "matched_keywords": keywords,
                "indicators": {"domain": [clean]},
                "indicator_only": True,
            },
        )

    def process_certificate_event(self, event_data: dict[str, Any]) -> list[CTIItem]:
        """Parse CertStream certificate_update event and create CTIItems for matching domains."""
        data = event_data.get("data", {})
        leaf_cert = data.get("leaf_cert", {})
        all_domains = leaf_cert.get("all_domains", [])
        if not isinstance(all_domains, list):
            return []

        issuer_info = leaf_cert.get("issuer", {})
        issuer = issuer_info.get("O") or issuer_info.get("CN") or "Unknown CA"

        items: list[CTIItem] = []
        seen_in_event: set[str] = set()

        for d in all_domains:
            if not isinstance(d, str):
                continue
            clean = d.strip().lower()
            if clean.startswith("*."):
                clean = clean[2:]
            if clean in seen_in_event or clean in self._cursor.seen_domains:
                continue

            matched, brand, kws = self.matches_brand_protection(clean)
            if matched:
                seen_in_event.add(clean)
                items.append(self._create_item(clean, brand, kws, issuer, all_domains))

        return items

    def _load_from_buffer(self) -> None:
        """Load pre-staged CertStream events from disk buffer file."""
        if not self.buffer_file.exists():
            return
        try:
            raw = self.buffer_file.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to read CertStream buffer %s: %s", self.buffer_file, exc)
            return

        if not isinstance(data, list):
            return

        for entry in data:
            if len(self._items) >= self.max_buffer_size:
                break
            if isinstance(entry, dict) and "data" in entry:
                new_items = self.process_certificate_event(entry)
                self._items.extend(new_items)
            elif isinstance(entry, dict) and "domain" in entry:
                d = str(entry["domain"]).strip().lower()
                if d.startswith("*."):
                    d = d[2:]
                if d in self._cursor.seen_domains or any(
                    it.identifier == f"certstream-{d}" for it in self._items
                ):
                    continue
                brand = str(entry.get("matched_brand") or "").strip()
                kws = list(entry.get("matched_keywords") or [])
                if not brand or not kws:
                    matched, auto_brand, auto_kws = self.matches_brand_protection(d)
                    if not matched:
                        continue
                    brand = brand or auto_brand
                    kws = kws or auto_kws
                issuer = str(entry.get("issuer") or "Buffered CA")
                all_d = entry.get("all_domains") or [d]
                self._items.append(self._create_item(d, brand, kws, issuer, all_d))
            elif isinstance(entry, str):
                d = entry.strip().lower()
                if d.startswith("*."):
                    d = d[2:]
                if d in self._cursor.seen_domains or any(
                    it.identifier == f"certstream-{d}" for it in self._items
                ):
                    continue
                matched, brand, kws = self.matches_brand_protection(d)
                if matched:
                    self._items.append(self._create_item(d, brand, kws, "Buffered CA", [d]))

    def _prune_from_buffer(self, domain: str) -> None:
        """Remove processed domain from buffer file to avoid bloat."""
        if not self.buffer_file.exists():
            return
        clean = domain.strip().lower()
        try:
            data = json.loads(self.buffer_file.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                return
            kept: list[Any] = []
            for entry in data:
                if isinstance(entry, str) and entry.strip().lower().removeprefix("*.") == clean:
                    continue
                if isinstance(entry, dict):
                    ent_dom = str(entry.get("domain") or "").strip().lower().removeprefix("*.")
                    if ent_dom == clean:
                        continue
                    all_doms = [
                        str(x).strip().lower().removeprefix("*.")
                        for x in entry.get("all_domains", [])
                    ]
                    if clean in all_doms:
                        continue
                kept.append(entry)
            self.buffer_file.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(self.buffer_file, json.dumps(kept, indent=2))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("Failed to prune domain %s from CertStream buffer: %s", domain, exc)

    def buffer_domain(
        self,
        domain: str,
        *,
        brand: str | None = None,
        keywords: list[str] | None = None,
        issuer: str = "Buffered CA",
        all_domains: list[str] | None = None,
    ) -> None:
        """Enqueue a domain event directly into the CertStream buffer file."""
        entries: list[Any] = []
        if self.buffer_file.exists():
            try:
                data = json.loads(self.buffer_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    entries = data
            except Exception:
                entries = []
        entries.append(
            {
                "domain": domain,
                "matched_brand": brand,
                "matched_keywords": keywords,
                "issuer": issuer,
                "all_domains": all_domains or [domain],
            }
        )
        self.buffer_file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.buffer_file, json.dumps(entries, indent=2))

    def buffer_event(self, event_data: dict[str, Any]) -> None:
        """Enqueue a raw CertStream certificate event into the buffer file."""
        entries: list[Any] = []
        if self.buffer_file.exists():
            try:
                data = json.loads(self.buffer_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    entries = data
            except Exception:
                entries = []
        entries.append(event_data)
        self.buffer_file.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.buffer_file, json.dumps(entries, indent=2))

    def _poll_stream(self, timeout_sec: float | None = None) -> None:
        """Connect to live CertStream websocket and buffer matching events."""
        timeout = timeout_sec if timeout_sec is not None else self.poll_timeout_sec
        start_time = time.monotonic()

        try:
            import websockets.sync.client
        except ImportError:
            log.warning("websockets library not available for CertStreamProvider.")
            return

        try:
            with websockets.sync.client.connect(self.stream_url, close_timeout=1.0) as ws:
                while time.monotonic() - start_time < timeout:
                    if len(self._items) >= self.max_buffer_size:
                        break
                    try:
                        raw_msg = ws.recv(
                            timeout=max(0.5, timeout - (time.monotonic() - start_time))
                        )
                        if isinstance(raw_msg, bytes):
                            raw_msg = raw_msg.decode("utf-8")
                        msg = json.loads(raw_msg)
                        new_items = self.process_certificate_event(msg)
                        self._items.extend(new_items)
                        if new_items:
                            break
                    except TimeoutError:
                        break
                    except Exception as e:
                        log.debug("CertStream recv loop exception: %s", e)
                        break
        except Exception as e:
            log.warning("CertStream websocket connection error: %s", e)

    def next_item(self) -> CTIItem | None:
        if not self._items:
            self._load_from_buffer()
        if not self._items:
            self._poll_stream()
        if not self._items:
            return None
        return self._items[0]

    def acknowledge(self, item: CTIItem) -> None:
        if self._items and self._items[0] == item:
            self._items.pop(0)

        domain = item.metadata.get("domain") or item.identifier.removeprefix("certstream-")
        if domain:
            self._cursor.record_domain(domain, self.cursor_file)
            self._prune_from_buffer(domain)
