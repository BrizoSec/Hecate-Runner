"""FIRST.org EPSS Exploit Prediction & Weaponization Spike CTI Provider.

Polls FIRST.org EPSS (Exploit Prediction Scoring System) live data to detect
vulnerabilities experiencing high weaponization probability and probability spikes.
Triggers autonomous proactive hunt drafting before widespread exploitation occurs.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)


class FirstOrgError(RuntimeError):
    """Raised when an operation on the FIRST.org EPSS provider fails."""


@dataclass
class FirstOrgCursorState:
    """Track processed CVEs and last update date from FIRST.org EPSS."""

    seen_cves: list[str] = field(default_factory=list)
    last_processed_date: str | None = None

    @classmethod
    def load(cls, path: Path) -> FirstOrgCursorState:
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                seen_cves=list(raw.get("seen_cves") or []),
                last_processed_date=raw.get("last_processed_date"),
            )
        except Exception as exc:
            log.warning("Failed to load FIRST.org cursor from %s: %s; starting clean", path, exc)
            return cls()

    def advance(self, cve: str, date: str | None = None) -> None:
        clean = cve.upper().strip()
        if clean and clean not in self.seen_cves:
            self.seen_cves.append(clean)
            if len(self.seen_cves) > 5000:
                self.seen_cves = self.seen_cves[-5000:]
        if date:
            self.last_processed_date = date

    def already_seen(self, cve: str) -> bool:
        return cve.upper().strip() in self.seen_cves

    def save(self, path: Path) -> None:
        payload = {
            "seen_cves": self.seen_cves,
            "last_processed_date": self.last_processed_date,
            "last_updated": datetime.now(UTC).isoformat(),
        }
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


class FirstOrgProvider(CTIProvider):
    """CTI provider consuming high-probability exploit predictions from FIRST.org EPSS."""

    name: str = "first_org"

    def __init__(
        self,
        cursor_file: Path,
        *,
        base_url: str = "https://api.first.org/data/v1/epss",
        min_epss: float = 0.50,
        min_percentile: float = 0.85,
        limit: int = 50,
        request_timeout_sec: float = 20.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.base_url = base_url.rstrip("/")
        self.min_epss = min_epss
        self.min_percentile = min_percentile
        self.limit = limit
        self.request_timeout_sec = request_timeout_sec
        self._external_client = client is not None
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={"User-Agent": "Hecate-Runner/1.0", "Accept": "application/json"},
            follow_redirects=True,
        )
        self._kev_cache: dict[str, dict[str, Any]] | None = None
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_cve_enrichment(self, cve: str) -> dict[str, Any]:
        """Cross-references the CVE against CISA KEV to enrich telemetry context."""
        if self._kev_cache is None:
            self._kev_cache = {}
            try:
                kev_resp = self._client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=10.0,
                )
                if kev_resp.status_code == 200:
                    vulns = kev_resp.json().get("vulnerabilities", [])
                    for v in vulns:
                        vid = str(v.get("cveID") or "").strip().upper()
                        if vid:
                            self._kev_cache[vid] = v
            except Exception as exc:
                log.debug("CISA KEV enrichment fetch omitted (%s)", exc)

        return self._kev_cache.get(cve.upper(), {})

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def poll(self) -> CTIItem | None:
        return self.next_item()

    def next_item(self) -> CTIItem | None:
        cursor = FirstOrgCursorState.load(self.cursor_file)
        try:
            params = {"order": "!epss", "limit": str(self.limit)}
            resp = self._client.get(self.base_url, params=params)
            if resp.status_code == 429:
                log.warning("FIRST.org EPSS rate limit exceeded (HTTP 429)")
                return None
            resp.raise_for_status()
            data = resp.json().get("data", [])
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            log.warning("Failed to query FIRST.org EPSS API: %s", exc)
            return None

        for entry in data:
            cve = str(entry.get("cve") or "").strip().upper()
            if not cve or cursor.already_seen(cve):
                continue

            try:
                epss = float(entry.get("epss") or 0.0)
                percentile = float(entry.get("percentile") or 0.0)
            except (ValueError, TypeError):
                continue

            if epss < self.min_epss or percentile < self.min_percentile:
                continue

            epss_date = str(entry.get("date") or datetime.now(UTC).strftime("%Y-%m-%d"))
            title = f"FIRST.org EPSS Spike: {cve} (Exploit Probability: {epss:.1%}, Top {max(0.01, (1.0 - percentile) * 100):.2f}%)"
            enrichment = self._get_cve_enrichment(cve)
            content = self._format_content(cve, epss, percentile, epss_date, enrichment=enrichment)

            metadata: dict[str, Any] = {
                "evidence_profile": "vulnerability_advisory",
                "cve": cve,
                "epss": epss,
                "percentile": percentile,
                "date": epss_date,
            }
            if enrichment:
                metadata["cisa_kev_enrichment"] = enrichment
                if enrichment.get("vendorProject"):
                    metadata["vendor"] = enrichment.get("vendorProject")
                if enrichment.get("product"):
                    metadata["product"] = enrichment.get("product")
                if enrichment.get("knownRansomwareCampaignUse"):
                    metadata["ransomware_use"] = enrichment.get("knownRansomwareCampaignUse")

            return CTIItem(
                content=content,
                source=self.name,
                received_at=datetime.now(UTC),
                identifier=f"first-org-{cve.lower()}",
                metadata=metadata,
                title=title,
                source_url="https://www.first.org/epss/",
            )

        return None

    def acknowledge(self, item: CTIItem) -> None:
        cve = str(item.metadata.get("cve") or "")
        date = str(item.metadata.get("date") or "")
        if cve:
            cursor = FirstOrgCursorState.load(self.cursor_file)
            cursor.advance(cve, date)
            cursor.save(self.cursor_file)

    def _format_content(
        self,
        cve: str,
        epss: float,
        percentile: float,
        date: str,
        enrichment: dict[str, Any] | None = None,
    ) -> str:
        lines = [
            f"Title: FIRST.org EPSS Exploit Weaponization Alert: {cve}",
            "Source: FIRST.org EPSS Exploit Prediction Engine",
            f"Vulnerability ID: {cve}",
            f"Published / Scored Date: {date}",
            f"Exploit Prediction Score (EPSS): {epss:.4f} ({epss:.1%} estimated probability of exploitation in next 30 days)",
            f"Global Threat Percentile: {percentile:.4f} (Higher threat than {percentile * 100:.2f}% of all indexed CVEs)",
        ]

        enrich = enrichment or {}
        if enrich:
            vendor = enrich.get("vendorProject") or "Unknown"
            product = enrich.get("product") or "Unknown"
            vuln_name = enrich.get("vulnerabilityName") or ""
            desc = enrich.get("shortDescription") or ""
            ransomware = enrich.get("knownRansomwareCampaignUse") or "Unknown"
            lines.extend(
                [
                    "",
                    "CISA KEV Vulnerability Context:",
                    f"- Vendor / Project: {vendor}",
                    f"- Product: {product}",
                ]
            )
            if vuln_name:
                lines.append(f"- Vulnerability Name: {vuln_name}")
            if desc:
                lines.append(f"- Description: {desc}")
            lines.append(f"- Known Ransomware Campaign Use: {ransomware}")

        lines.extend(
            [
                "",
                "Threat Intelligence Summary:",
                f"FIRST.org EPSS model has flagged {cve} with an elevated weaponization probability of {epss:.1%}. "
                "High EPSS percentiles indicate active adversary targeting, public exploit availability, or rapid weaponization velocity. "
                "Defenders should proactively hunt for exploitation attempts across external perimeters, web applications, and network services.",
                "",
                "Attack Context & Threat Vectors:",
                f"- Targeted Vulnerability: {cve}",
                "- Exploitation Vector: Remote Code Execution, Authentication Bypass, or Privilege Escalation",
                "- Recommended Monitoring: Outbound reverse shells, unexpected child processes under web/service accounts, abnormal memory pool corruption.",
                "",
                f"{ATTACK_TECHNIQUE_LINE} T1190, T1210, T1068",
            ]
        )
        return "\n".join(lines)
