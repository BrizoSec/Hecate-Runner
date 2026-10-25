"""VulnCheck Known Exploited Vulnerabilities (KEV) CTI provider.

Queries the VulnCheck API (https://api.vulncheck.com/v3/index/vulncheck-kev) to ingest
real-time weaponized, in-the-wild exploited vulnerabilities, associated threat actor
attribution, and detection opportunities before vendor advisories mature.
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

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class VulnCheckError(RuntimeError):
    """Raised when an operation on the VulnCheck provider fails."""


@dataclass
class VulnCheckCursorState:
    """Track processed VulnCheck CVE identifiers and timestamps."""

    seen_cves: list[str] = field(default_factory=list)
    last_date_added: str | None = None

    @classmethod
    def load(cls, path: Path) -> VulnCheckCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                seen_cves=list(data.get("seen_cves", [])),
                last_date_added=data.get("last_date_added"),
            )
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            log.warning("VulnCheck cursor %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(
            path,
            json.dumps(
                {
                    "seen_cves": self.seen_cves[-1000:],
                    "last_date_added": self.last_date_added,
                },
                indent=2,
            ),
        )

    def already_seen(self, cve: str) -> bool:
        return cve.upper() in self.seen_cves

    def advance(self, cve: str, date_added: str | None = None) -> None:
        cve_upper = cve.upper()
        if cve_upper and cve_upper not in self.seen_cves:
            self.seen_cves.append(cve_upper)
        if date_added:
            self.last_date_added = date_added


def _infer_attack_techniques(vuln: dict[str, Any]) -> list[str]:
    """Infer relevant MITRE ATT&CK techniques from vulnerability metadata."""
    techniques: list[str] = []
    desc = str(vuln.get("short_description") or vuln.get("name") or "").lower()
    tags = [str(t).lower() for t in (vuln.get("vulncheck_tags") or [])]
    exploit_type = str(vuln.get("exploit_type") or "").lower()

    # Remote / Public-facing exploitation
    if (
        any(
            k in desc
            for k in (
                "remote code execution",
                "rce",
                "unauthenticated",
                "pre-auth",
                "public-facing",
                "bypass",
                "upload",
            )
        )
        or "initial access" in tags
        or "remote" in exploit_type
    ):
        techniques.append("T1190")  # Exploit Public-Facing Application

    # Privilege escalation
    if (
        any(
            k in desc
            for k in (
                "privilege escalation",
                "elevation of privilege",
                "lpe",
                "root",
                "system privilege",
            )
        )
        or "privilege escalation" in tags
    ):
        techniques.append("T1068")  # Exploitation for Privilege Escalation

    # Client-side exploitation
    if any(k in desc for k in ("browser", "word", "excel", "pdf", "reader", "outlook", "client")):
        techniques.append("T1203")  # Exploitation for Client Execution

    # Lateral movement / remote services
    if any(
        k in desc
        for k in (
            "smb",
            "rpc",
            "winrm",
            "active directory",
            "lateral movement",
            "domain controller",
        )
    ):
        techniques.append("T1210")  # Exploitation of Remote Services

    # Default to T1190 if weaponized or in-the-wild and no specific technique was inferred
    if not techniques:
        techniques.append("T1190")

    return sorted(techniques)


class VulnCheckProvider(CTIProvider):
    """CTI provider consuming weaponized, actively exploited vulnerabilities from VulnCheck KEV."""

    name: str = "vulncheck"

    def __init__(
        self,
        cursor_file: Path,
        api_key: str | None = None,
        base_url: str = "https://api.vulncheck.com/v3/index/vulncheck-kev",
        max_age_days: int = 30,
        request_timeout_sec: float = 20.0,
        client: httpx.Client | None = None,
    ):
        self.cursor_file = cursor_file
        self.api_key = api_key
        self.base_url = base_url
        self.max_age_days = max_age_days
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
            log.debug("VulnCheck provider skipped: VULNCHECK_API_KEY is not configured")
            return None

        cursor = VulnCheckCursorState.load(self.cursor_file)
        try:
            items = self._fetch_kev_items()
        except VulnCheckError as exc:
            log.warning("Failed to fetch VulnCheck KEV catalog: %s", exc)
            return None

        candidates: list[dict[str, Any]] = []
        for item in items:
            cves = item.get("cve") or []
            if isinstance(cves, str):
                cves = [cves]
            cve_id = cves[0] if cves else ""
            if not cve_id or cursor.already_seen(cve_id):
                continue
            candidates.append(item)

        if not candidates:
            log.debug("No new unrouted vulnerabilities in VulnCheck KEV catalog")
            return None

        # Process oldest unrouted entry first
        candidates.sort(key=lambda x: str(x.get("date_added") or ""))
        return self._vuln_to_cti_item(candidates[0])

    def acknowledge(self, item: CTIItem) -> None:
        cve = item.metadata.get("cve") or item.identifier
        date_added = item.metadata.get("date_added")
        if not cve:
            log.warning("Cannot acknowledge VulnCheck item without CVE identifier (%r)", item)
            return
        cursor = VulnCheckCursorState.load(self.cursor_file)
        cursor.advance(str(cve), date_added)
        cursor.save(self.cursor_file)

    def _fetch_kev_items(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self.base_url)
        except httpx.RequestError as exc:
            raise VulnCheckError(f"HTTP request to {self.base_url} failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise VulnCheckError(
                f"Authentication failure (HTTP {resp.status_code}); check VULNCHECK_API_KEY"
            )
        if resp.status_code == 429:
            raise VulnCheckError("VulnCheck API rate limit reached (HTTP 429)")
        if resp.status_code != 200:
            raise VulnCheckError(f"HTTP {resp.status_code} from {self.base_url}")

        data = resp.json()
        return list(data.get("data") or [])

    def _vuln_to_cti_item(self, vuln: dict[str, Any]) -> CTIItem:
        cves = vuln.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]
        cve_id = cves[0] if cves else "CVE-UNKNOWN"
        name = str(vuln.get("name") or cve_id).strip()
        vendor = str(vuln.get("vendor") or "Unknown Vendor").strip()
        product = str(vuln.get("product") or "Unknown Product").strip()
        date_added = str(vuln.get("date_added") or "")
        exploit_type = str(vuln.get("exploit_type") or "Actively Exploited").strip()
        in_the_wild = bool(vuln.get("vulncheck_reported_exploitation", True))
        actors = [str(a) for a in (vuln.get("threat_actors") or []) if str(a).strip()]
        tags = [str(t) for t in (vuln.get("vulncheck_tags") or []) if str(t).strip()]
        desc = str(vuln.get("short_description") or "").strip()
        refs = [str(r) for r in (vuln.get("references") or []) if str(r).strip()]

        techniques = _infer_attack_techniques(vuln)
        title = f"VulnCheck KEV: {cve_id} - {vendor} {product} {name}"
        link = f"https://vulncheck.com/cve/{cve_id}"

        # Construct prompt blurb
        lines = [
            f"VulnCheck KEV: {cve_id}",
            "Source: VulnCheck Known Exploited Vulnerabilities",
            f"Link: {link}",
            f"Target System: {vendor} {product}",
            f"Exploit Maturity: {exploit_type.upper()} ({'Observed in-the-wild' if in_the_wild else 'Weaponized PoC'})",
        ]
        if actors:
            lines.append(f"Associated Threat Actors: {', '.join(actors[:6])}")
        if tags:
            lines.append(f"Tags: {', '.join(tags[:8])}")
        if techniques:
            lines.append(f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques)}")

        if desc:
            lines.append(f"\nExploitation Context & Attack Description:\n{desc}")

        if refs:
            lines.append(
                "\nExploit & Advisory References:\n" + "\n".join(f"  - {r}" for r in refs[:4])
            )

        content = "\n".join(lines)

        metadata = {
            "cve": cve_id,
            "vendor": vendor,
            "product": product,
            "exploit_type": exploit_type,
            "date_added": date_added,
            "threat_actors": actors,
            "techniques": techniques,
            "indicators": {"cve": [cve_id]},
            "evidence_profile": "vulnerability_exploitation",
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=datetime.now(UTC),
            identifier=cve_id,
            metadata=metadata,
            title=title,
            source_url=link,
        )
