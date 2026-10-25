"""Censys C2 infrastructure & TLS fingerprinting CTI provider.

Queries Censys Search 2.0 / Platform API to monitor and ingest newly discovered
adversary Command-and-Control (C2) servers (Cobalt Strike, Sliver, Mythic, Havoc,
Metasploit, Brute Ratel) and their JARM/JA4 TLS fingerprints.
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


class CensysError(RuntimeError):
    """Raised when an operation on the Censys C2 provider fails."""


@dataclass
class CensysCursorState:
    """Track processed Censys host IP and port combinations."""

    seen_endpoints: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> CensysCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_endpoints=list(data.get("seen_endpoints", [])))
        except (json.JSONDecodeError, TypeError, OSError) as exc:
            log.warning("Censys C2 cursor %s corrupt (%s); resetting", path, exc)
            return cls()

    def save(self, path: Path) -> None:
        atomic_write_text(
            path, json.dumps({"seen_endpoints": self.seen_endpoints[-1000:]}, indent=2)
        )

    def already_seen(self, endpoint: str) -> bool:
        return endpoint in self.seen_endpoints

    def advance(self, endpoint: str) -> None:
        if endpoint and endpoint not in self.seen_endpoints:
            self.seen_endpoints.append(endpoint)


class CensysC2Provider(CTIProvider):
    """CTI provider consuming adversary C2 listener infrastructure from Censys."""

    name: str = "censys_c2"

    def __init__(
        self,
        cursor_file: Path,
        api_token: str | None = None,
        base_url: str = "https://search.censys.io/api/v2/hosts/search",
        query: str = "services.service_name: (COBALT_STRIKE or SLIVER or MYTHIC or HAVOC)",
        request_timeout_sec: float = 20.0,
        client: httpx.Client | None = None,
    ):
        self.cursor_file = cursor_file
        self.api_token = api_token
        self.base_url = base_url
        self.query = query
        self.request_timeout_sec = request_timeout_sec
        if client is not None:
            self._client = client
            if api_token and "Authorization" not in self._client.headers:
                self._client.headers["Authorization"] = f"Bearer {api_token}"
        else:
            self._client = httpx.Client(
                timeout=request_timeout_sec,
                headers={
                    "User-Agent": "Hecate-Runner/1.0",
                    "Accept": "application/json",
                    **({"Authorization": f"Bearer {api_token}"} if api_token else {}),
                },
                follow_redirects=True,
            )
        self._owns_client = client is None
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def next_item(self) -> CTIItem | None:
        if not self.api_token:
            log.debug("Censys C2 provider skipped: CENSYS_API_TOKEN is not configured")
            return None

        cursor = CensysCursorState.load(self.cursor_file)
        try:
            hits = self._search_c2_hosts()
        except CensysError as exc:
            log.warning("Failed to query Censys C2 infrastructure: %s", exc)
            return None

        for hit in hits:
            ip = str(hit.get("ip") or "").strip()
            if not ip:
                continue

            services = hit.get("services") or [{}]
            port = str(services[0].get("port") or "443")
            endpoint = f"{ip}:{port}"

            if cursor.already_seen(endpoint):
                continue

            return self._hit_to_cti_item(endpoint, ip, port, hit)

        log.debug("No new unrouted Censys C2 infrastructure candidates")
        return None

    def acknowledge(self, item: CTIItem) -> None:
        endpoint = item.metadata.get("endpoint") or item.identifier
        if not endpoint:
            log.warning("Cannot acknowledge Censys item without endpoint identifier (%r)", item)
            return
        cursor = CensysCursorState.load(self.cursor_file)
        cursor.advance(str(endpoint))
        cursor.save(self.cursor_file)

    def _search_c2_hosts(self) -> list[dict[str, Any]]:
        params: dict[str, str | int] = {"q": self.query, "per_page": 20}
        try:
            resp = self._client.get(self.base_url, params=params)
        except httpx.RequestError as exc:
            raise CensysError(f"HTTP request to {self.base_url} failed: {exc}") from exc

        if resp.status_code in (401, 403):
            raise CensysError(
                f"Authentication failure (HTTP {resp.status_code}); check CENSYS_API_TOKEN"
            )
        if resp.status_code == 422:
            raise CensysError("Censys API balance limit reached (insufficient credits)")
        if resp.status_code == 429:
            raise CensysError("Censys rate limit exceeded (HTTP 429)")
        if resp.status_code != 200:
            raise CensysError(f"HTTP {resp.status_code} from {self.base_url}")

        data = resp.json().get("result") or resp.json()
        return list(data.get("hits") or [])

    def _hit_to_cti_item(self, endpoint: str, ip: str, port: str, hit: dict[str, Any]) -> CTIItem:
        services = hit.get("services") or []
        location = hit.get("location") or {}
        autonomous_system = hit.get("autonomous_system") or {}

        country = location.get("country") or "Unknown"
        asn = autonomous_system.get("asn") or ""
        as_name = autonomous_system.get("name") or "Unknown"

        frameworks: list[str] = []
        jarm_hashes: list[str] = []
        ja4_hashes: list[str] = []
        cert_subjects: list[str] = []

        for s in services:
            svc_name = str(s.get("service_name") or "")
            if svc_name and svc_name.upper() not in frameworks:
                frameworks.append(svc_name.upper())

            tls = s.get("tls") or {}
            jarm = tls.get("jarm") or s.get("jarm")
            if jarm and str(jarm) not in jarm_hashes:
                jarm_hashes.append(str(jarm))
            ja4 = tls.get("ja4") or s.get("ja4")
            if ja4 and str(ja4) not in ja4_hashes:
                ja4_hashes.append(str(ja4))

            cert = tls.get("certificate") or {}
            subj = cert.get("parsed", {}).get("subject_dn") or cert.get("subject_dn")
            if subj and str(subj) not in cert_subjects:
                cert_subjects.append(str(subj))

        fw_name = ", ".join(frameworks) if frameworks else "Adversary C2 Listener"
        title = f"Censys C2 Exposure: {fw_name} ({endpoint})"
        link = f"https://search.censys.io/hosts/{ip}"

        lines = [
            f"Censys C2 Exposure: {fw_name}",
            "Source: Censys Internet Intelligence",
            f"Link: {link}",
            f"Adversary Host: {ip}",
            f"Listener Port: {port}",
            f"Location & Origin: {country} (AS{asn} - {as_name})",
            f"{ATTACK_TECHNIQUE_LINE} T1071.001, T1571",
        ]

        fingerprints = []
        if jarm_hashes:
            fingerprints.append(f"JARM: {', '.join(jarm_hashes[:2])}")
        if ja4_hashes:
            fingerprints.append(f"JA4: {', '.join(ja4_hashes[:2])}")
        if cert_subjects:
            fingerprints.append(f"TLS Subject: {', '.join(cert_subjects[:2])}")
        if fingerprints:
            lines.append(f"\nTLS & Listener Fingerprints:\n  {'; '.join(fingerprints)}")

        lines.append(
            "\nDetection Opportunity:\n"
            "Monitor outbound perimeter network connections and TLS client hellos "
            f"connecting to {endpoint} or matching server TLS configuration."
        )

        content = "\n".join(lines)

        indicators: dict[str, list[str]] = {"ipv4": [ip]}
        if jarm_hashes:
            indicators["jarm"] = jarm_hashes
        if ja4_hashes:
            indicators["ja4"] = ja4_hashes

        metadata = {
            "endpoint": endpoint,
            "ip": ip,
            "port": port,
            "frameworks": frameworks,
            "jarm": jarm_hashes,
            "ja4": ja4_hashes,
            "techniques": ["T1071.001", "T1571"],
            "indicators": indicators,
            "evidence_profile": "infrastructure_telemetry",
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=datetime.now(UTC),
            identifier=endpoint,
            metadata=metadata,
            title=title,
            source_url=link,
        )
