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
    ) -> None:
        self.cursor_file = cursor_file
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
                blurb_lines = [
                    "CertStream Alert: Potential Brand Impersonation / Staging Domain",
                    "Indicators (1 total): domain (1)\n",
                    f"Domain: {clean}",
                    f"Subject Alternative Names: {', '.join(str(s) for s in all_domains[:5])}",
                    f"Issuer: {issuer}",
                    f"Target Brand Match: {brand}",
                    f"Matched Staging Patterns: {', '.join(kws)}",
                    "Threat Context: Newly issued SSL certificate matches high-value target brand and suspicious staging keywords, indicating adversary infrastructure staging or ClickFix lure setup.",
                    f"Certificate Transparency Query: https://crt.sh/?q={clean}",
                ]
                content = "\n".join(blurb_lines)
                item = CTIItem(
                    content=content,
                    source="certstream",
                    identifier=f"certstream-{clean}",
                    title=f"Suspicious Certificate Staged: {clean}",
                    source_url=f"https://crt.sh/?q={clean}",
                    metadata={
                        "domain": clean,
                        "all_domains": all_domains,
                        "issuer": issuer,
                        "matched_brand": brand,
                        "matched_keywords": kws,
                    },
                )
                items.append(item)

        return items

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
