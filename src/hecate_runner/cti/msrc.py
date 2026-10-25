"""Microsoft Security Response Center (MSRC) structured vulnerability & cloud advisory CTI provider.

Ingests authoritative vulnerability disclosures, security update bulletins, and exploitability
assessments from the Microsoft Security Response Center (https://api.msrc.microsoft.com).
Prioritizes in-the-wild exploitation, remote code execution, elevation of privilege,
and cloud/identity assets (Entra ID, Azure, Exchange, Hyper-V, Windows Server).
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")


class MsrcError(RuntimeError):
    """Raised when an operation on the MSRC provider fails."""


@dataclass
class MsrcCursorState:
    """Track processed MSRC vulnerability identifiers and document releases."""

    seen_cves: list[str] = field(default_factory=list)
    seen_docs: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> MsrcCursorState:
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(
                seen_cves=list(raw.get("seen_cves") or []),
                seen_docs=list(raw.get("seen_docs") or []),
            )
        except Exception as exc:
            log.warning("Failed to load MSRC cursor from %s: %s; starting clean", path, exc)
            return cls()

    def advance(self, cve: str) -> None:
        if cve and cve not in self.seen_cves:
            self.seen_cves.append(cve)
            if len(self.seen_cves) > 5000:
                self.seen_cves = self.seen_cves[-5000:]

    def save(self, path: Path) -> None:
        payload = {
            "seen_cves": self.seen_cves,
            "seen_docs": self.seen_docs,
            "last_updated": datetime.now(UTC).isoformat(),
        }
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


class MsrcProvider(CTIProvider):
    """Ingests high-priority security vulnerabilities and guidance from Microsoft MSRC."""

    name: str = "msrc"

    def __init__(
        self,
        cursor_file: Path,
        *,
        updates_url: str = "https://api.msrc.microsoft.com/cvrf/v2.0/updates",
        doc_base_url: str = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/",
        max_age_days: int = 90,
        request_timeout_sec: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.updates_url = updates_url
        self.doc_base_url = doc_base_url
        self.max_age_days = max_age_days
        self.request_timeout_sec = request_timeout_sec
        self._external_client = client is not None
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={
                "Accept": "application/json",
                "User-Agent": "Hecate-Runner/1.0",
            },
        )

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def next_item(self) -> CTIItem | None:
        return self.poll()

    def poll(self) -> CTIItem | None:
        cursor = MsrcCursorState.load(self.cursor_file)
        seen_set = set(cursor.seen_cves)

        try:
            updates = self._fetch_updates_index()
        except MsrcError as exc:
            log.warning("MSRC updates index fetch failed: %s", exc)
            return None

        cutoff = datetime.now(UTC) - timedelta(days=self.max_age_days)

        for update_meta in updates:
            doc_id = str(update_meta.get("ID") or "")
            if not doc_id:
                continue

            rel_date_raw = update_meta.get("CurrentReleaseDate") or update_meta.get(
                "InitialReleaseDate"
            )
            if rel_date_raw:
                with contextlib.suppress(ValueError):
                    rel_dt = datetime.fromisoformat(str(rel_date_raw).replace("Z", "+00:00"))
                    if rel_dt < cutoff:
                        continue

            try:
                doc = self._fetch_document(doc_id)
            except MsrcError as exc:
                log.warning("Failed to fetch MSRC document %s: %s", doc_id, exc)
                continue

            vulns = doc.get("Vulnerability") or []
            for vuln in vulns:
                cve = str(vuln.get("CVE") or "").strip().upper()
                if not cve or cve in seen_set:
                    continue

                item = self._vuln_to_cti_item(doc_id, vuln)
                if item:
                    log.info("MSRC provider routed candidate %s (%s)", item.identifier, item.title)
                    return item

        log.debug("No new unrouted MSRC security advisories found")
        return None

    def acknowledge(self, item: CTIItem) -> None:
        cve = item.metadata.get("cve") or item.identifier
        if not cve:
            log.warning("Cannot acknowledge MSRC item without CVE identifier (%r)", item)
            return
        cursor = MsrcCursorState.load(self.cursor_file)
        cursor.advance(str(cve))
        cursor.save(self.cursor_file)

    def _fetch_updates_index(self) -> list[dict[str, Any]]:
        try:
            resp = self._client.get(self.updates_url)
        except httpx.RequestError as exc:
            raise MsrcError(f"HTTP request to {self.updates_url} failed: {exc}") from exc

        if resp.status_code != 200:
            raise MsrcError(f"HTTP {resp.status_code} from {self.updates_url}")

        data = resp.json()
        values = data.get("value") or []
        # Sort in reverse chronological order so newest months are evaluated first
        return list(reversed(values))

    def _fetch_document(self, doc_id: str) -> dict[str, Any]:
        url = f"{self.doc_base_url.rstrip('/')}/{doc_id}"
        try:
            resp = self._client.get(url)
        except httpx.RequestError as exc:
            raise MsrcError(f"HTTP request to {url} failed: {exc}") from exc

        if resp.status_code != 200:
            raise MsrcError(f"HTTP {resp.status_code} from {url}")

        data = resp.json()
        return data if isinstance(data, dict) else {}

    def _vuln_to_cti_item(self, doc_id: str, vuln: dict[str, Any]) -> CTIItem | None:
        cve = str(vuln.get("CVE") or "").strip().upper()
        title_dict = vuln.get("Title") or {}
        title = title_dict.get("Value") if isinstance(title_dict, dict) else str(title_dict)
        if not title:
            title = f"{cve} Security Vulnerability"

        # CVSS Base score
        cvss_score: float = 0.0
        cvss_vector: str = ""
        for s in vuln.get("CVSSScoreSets") or []:
            try:
                score = float(s.get("BaseScore") or 0.0)
                if score > cvss_score:
                    cvss_score = score
                    cvss_vector = str(s.get("Vector") or "")
            except (ValueError, TypeError):
                continue

        # Threats: Severity, Impact, Exploitability
        severity = ""
        impact = ""
        exploitability = ""
        threats = vuln.get("Threats") or []
        for t in threats:
            t_type = t.get("Type")
            desc = (
                t.get("Description", {}).get("Value")
                if isinstance(t.get("Description"), dict)
                else str(t.get("Description") or "")
            )
            if t_type == 3 and not severity:
                severity = desc
            elif t_type == 0 and not impact:
                impact = desc
            elif "Exploited:" in desc or "Exploitation" in desc:
                exploitability = desc

        # Filter out minor informational updates (keep Critical/Important or CVSS >= 7.0 or exploited)
        is_exploited = (
            "Exploited:Yes" in exploitability or "Exploitation Detected" in exploitability
        )
        is_high_impact = (
            cvss_score >= 7.0 or severity.lower() in ("critical", "important") or is_exploited
        )
        if not is_high_impact and cvss_score > 0.0:
            return None

        # Extract MITRE ATT&CK techniques based on vulnerability type & impact
        techniques: list[str] = []
        lowered_text = f"{title} {impact} {exploitability}".lower()
        if "remote code execution" in lowered_text or "rce" in lowered_text:
            techniques.extend(["T1190", "T1210"])
        elif "elevation of privilege" in lowered_text or "privilege escalation" in lowered_text:
            techniques.append("T1068")
        elif "security feature bypass" in lowered_text or "tampering" in lowered_text:
            techniques.append("T1562.001")
        elif "information disclosure" in lowered_text:
            techniques.append("T1005")
        elif "spoofing" in lowered_text:
            techniques.append("T1566.002")

        if any(k in lowered_text for k in ("azure", "entra", "oauth", "cloud", "active directory")):
            techniques.append("T1078.004")

        if not techniques:
            techniques.append("T1190")

        # Parse publication date
        pub_dt = datetime.now(UTC)
        raw_date = vuln.get("ReleaseDate") or vuln.get("RevisionHistory", [{}])[0].get("Date")
        if raw_date:
            with contextlib.suppress(ValueError):
                pub_dt = datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))

        # Build procedural guidance content
        lines = [
            f"Microsoft Security Response Center (MSRC) Advisory: {cve}",
            f"Release Document: {doc_id}",
            f"Vulnerability Title: {title}",
        ]
        if severity:
            lines.append(f"Severity: {severity}")
        if cvss_score > 0.0:
            lines.append(f"CVSS v3 Score: {cvss_score} ({cvss_vector})")
        if impact:
            lines.append(f"Vulnerability Impact: {impact}")
        if exploitability:
            lines.append(f"Exploitability Assessment: {exploitability}")

        # Notes & remediation guidance
        for note in vuln.get("Notes") or []:
            note_val = note.get("Value") if isinstance(note, dict) else str(note)
            if note_val:
                clean_note = re.sub(r"<[^>]+>", " ", str(note_val)).strip()
                if clean_note and len(clean_note) > 15:
                    lines.append(f"Advisory Guidance: {clean_note[:400]}")
                    break

        lines.append(f"{ATTACK_TECHNIQUE_LINE}: {', '.join(sorted(set(techniques)))}")

        item_title = f"MSRC Security Advisory: {cve} - {title}"
        link = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"

        content = "\n".join(lines)
        metadata = {
            "source": "msrc",
            "cve": cve,
            "doc_id": doc_id,
            "severity": severity,
            "cvss": cvss_score,
            "impact": impact,
            "exploitability": exploitability,
            "evidence_profile": "vulnerability_advisory",
            "techniques": sorted(set(techniques)),
            "indicators": {"cve": [cve]},
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=pub_dt,
            identifier=f"msrc-{cve.lower()}",
            metadata=metadata,
            title=item_title,
            source_url=link,
        )
