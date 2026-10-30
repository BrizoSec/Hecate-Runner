"""OpenCTI STIX 2.1 & GraphQL Platform CTI Provider.

Connects to OpenCTI instances via GraphQL API to ingest structured threat intelligence,
including Reports, Intrusion Sets, Threat Actors, Attack Patterns (ATT&CK techniques),
and Indicator observables.

When unconfigured, falls back to an upstream test STIX fixture, not live intelligence.
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
_STIX_IPV4_RE = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)
_STIX_DOMAIN_RE = re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE)
_STIX_URL_RE = re.compile(r"url:value\s*=\s*'([^']+)'", re.IGNORECASE)
_STIX_HASH_RE = re.compile(
    r"file:hashes\.(?:'[^']+'|[A-Za-z0-9_-]+)\s*=\s*'([a-fA-F0-9]{32,64})'", re.IGNORECASE
)


def extract_stix_observables(
    objects: list[dict[str, Any]],
    raw_patterns: list[str] | None = None,
) -> dict[str, list[str]]:
    """Extracts STIX 2.1 Cyber Observables (SCOs) into categorized indicator lists."""
    indicators: dict[str, set[str]] = {
        "ipv4": set(),
        "domain": set(),
        "url": set(),
        "sha256": set(),
        "md5": set(),
    }

    def _process_pattern(pat: str) -> None:
        if not pat:
            return
        for ip in _STIX_IPV4_RE.findall(pat):
            indicators["ipv4"].add(ip.strip())
        for dom in _STIX_DOMAIN_RE.findall(pat):
            indicators["domain"].add(dom.strip())
        for u in _STIX_URL_RE.findall(pat):
            indicators["url"].add(u.strip())
        for h in _STIX_HASH_RE.findall(pat):
            clean = h.strip().lower()
            if len(clean) == 64:
                indicators["sha256"].add(clean)
            elif len(clean) == 32:
                indicators["md5"].add(clean)

    # 1. Parse objects directly
    for obj in objects:
        otype = str(obj.get("type") or "").lower()
        if otype == "ipv4-addr":
            val = str(obj.get("value") or "").strip()
            if val:
                indicators["ipv4"].add(val)
        elif otype == "domain-name":
            val = str(obj.get("value") or "").strip()
            if val:
                indicators["domain"].add(val)
        elif otype == "url":
            val = str(obj.get("value") or "").strip()
            if val:
                indicators["url"].add(val)
        elif otype == "file":
            hashes = obj.get("hashes")
            if isinstance(hashes, dict):
                for h in hashes.values():
                    clean = str(h).strip().lower()
                    if len(clean) == 64:
                        indicators["sha256"].add(clean)
                    elif len(clean) == 32:
                        indicators["md5"].add(clean)

        _process_pattern(str(obj.get("pattern") or ""))

    # 2. Parse any extra raw patterns
    for pat in raw_patterns or []:
        _process_pattern(pat)

    return {k: sorted(v) for k, v in indicators.items() if v}


_OPENCTI_GRAPHQL_QUERY = """
query GetReports($first: Int) {
  reports(first: $first, orderBy: published, orderMode: desc) {
    edges {
      node {
        id
        standard_id
        name
        description
        published
        confidence
        objectMarking {
          definition
        }
        objects {
          edges {
            node {
              ... on AttackPattern {
                id
                name
                x_mitre_id
              }
              ... on Indicator {
                id
                name
                pattern
              }
              ... on ThreatActor {
                id
                name
              }
              ... on Malware {
                id
                name
              }
            }
          }
        }
      }
    }
  }
}
"""


class OpenCTIError(RuntimeError):
    """Raised when an operation on the OpenCTI provider fails."""


@dataclass
class OpenCTICursorState:
    """Track processed OpenCTI report IDs."""

    seen_ids: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> OpenCTICursorState:
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_ids=list(raw.get("seen_ids") or []))
        except Exception as exc:
            log.warning("Failed to load OpenCTI cursor from %s: %s; starting clean", path, exc)
            return cls()

    def advance(self, report_id: str) -> None:
        clean = report_id.strip()
        if clean and clean not in self.seen_ids:
            self.seen_ids.append(clean)
            if len(self.seen_ids) > 5000:
                self.seen_ids = self.seen_ids[-5000:]

    def already_seen(self, report_id: str) -> bool:
        return report_id.strip() in self.seen_ids

    def save(self, path: Path) -> None:
        payload = {
            "seen_ids": self.seen_ids,
            "last_updated": datetime.now(UTC).isoformat(),
        }
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


class OpenCTIProvider(CTIProvider):
    """CTI provider consuming reports and STIX 2.1 intelligence from OpenCTI."""

    name: str = "opencti"

    def __init__(
        self,
        cursor_file: Path,
        *,
        base_url: str | None = None,
        api_token: str | None = None,
        limit: int = 25,
        request_timeout_sec: float = 25.0,
        fallback_stix_url: str = "https://raw.githubusercontent.com/OpenCTI-Platform/client-python/master/tests/data/DATA-TEST-STIX2_v2.json",
        client: httpx.Client | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.base_url = (base_url or "").rstrip("/")
        self.api_token = api_token
        self.limit = limit
        self.request_timeout_sec = request_timeout_sec
        self.fallback_stix_url = fallback_stix_url
        self._external_client = client is not None
        if client is not None:
            self._client = client
            if api_token and "Authorization" not in self._client.headers:
                self._client.headers["Authorization"] = f"Bearer {api_token}"
        else:
            self._client = httpx.Client(
                timeout=request_timeout_sec,
                headers={
                    "User-Agent": "Hecate-Runner/1.0",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    **({"Authorization": f"Bearer {api_token}"} if api_token else {}),
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
        cursor = OpenCTICursorState.load(self.cursor_file)

        # Mode 1: GraphQL API when base_url and api_token are configured
        if self.base_url and self.api_token:
            try:
                item = self._poll_graphql(cursor)
                if item:
                    return item
            except Exception as exc:
                log.warning(
                    "OpenCTI GraphQL poll failed on %s: %s; falling back to STIX feed",
                    self.base_url,
                    exc,
                )

        # Mode 2: Upstream test STIX fixture (not a live OpenCTI instance)
        return self._poll_stix_fallback(cursor)

    def _poll_graphql(self, cursor: OpenCTICursorState) -> CTIItem | None:
        url = f"{self.base_url}/graphql"
        resp = self._client.post(
            url,
            json={"query": _OPENCTI_GRAPHQL_QUERY, "variables": {"first": self.limit}},
        )
        if resp.status_code == 429:
            log.warning("OpenCTI rate limit exceeded (HTTP 429)")
            return None
        resp.raise_for_status()

        data = resp.json().get("data", {}).get("reports", {}).get("edges", [])
        for edge in data:
            node = edge.get("node") or {}
            report_id = str(node.get("standard_id") or node.get("id") or "").strip()
            if not report_id or cursor.already_seen(report_id):
                continue

            name = str(node.get("name") or "OpenCTI Intelligence Report")
            description = str(node.get("description") or "")
            published = str(node.get("published") or datetime.now(UTC).isoformat())

            techniques: set[str] = set()
            actors: list[str] = []
            malware: list[str] = []
            indicators: list[str] = []
            patterns: list[str] = []
            raw_objects: list[dict[str, Any]] = []

            for obj_edge in node.get("objects", {}).get("edges", []):
                obj = obj_edge.get("node") or {}
                raw_objects.append(obj)
                if obj.get("x_mitre_id"):
                    techniques.add(str(obj["x_mitre_id"]))
                elif "standard_id" in obj and "attack-pattern" in str(obj["standard_id"]):
                    for t in _TECHNIQUE_RE.findall(str(obj.get("name") or "")):
                        techniques.add(t)

                if "pattern" in obj:
                    pat_str = str(obj["pattern"])
                    patterns.append(pat_str)
                    indicators.append(str(obj.get("name") or pat_str))
                elif obj.get("id", "").startswith("threat-actor--"):
                    actors.append(str(obj.get("name") or ""))
                elif obj.get("id", "").startswith("malware--"):
                    malware.append(str(obj.get("name") or ""))

            structured_indicators = extract_stix_observables(raw_objects, raw_patterns=patterns)

            # Combine named indicators and structured observables for display
            display_indicators = list(indicators)
            for cat, vals in structured_indicators.items():
                for v in vals:
                    item_str = f"{cat}: {v}"
                    if item_str not in display_indicators and v not in display_indicators:
                        display_indicators.append(item_str)

            content = self._format_report(
                name,
                description,
                published,
                actors,
                malware,
                sorted(techniques),
                display_indicators,
            )

            metadata: dict[str, Any] = {
                "evidence_profile": "procedural_intrusion",
                "report_id": report_id,
                "actors": actors,
                "malware": malware,
            }
            if structured_indicators:
                metadata["indicators"] = structured_indicators

            return CTIItem(
                content=content,
                source=self.name,
                received_at=datetime.now(UTC),
                identifier=f"opencti-{report_id[:32]}",
                metadata=metadata,
                title=f"OpenCTI: {name}",
                source_url=f"{self.base_url}/dashboard/analyses/reports/{node.get('id')}",
            )

        return None

    def _poll_stix_fallback(self, cursor: OpenCTICursorState) -> CTIItem | None:
        try:
            resp = self._client.get(self.fallback_stix_url)
            resp.raise_for_status()
            bundle = resp.json()
        except Exception as exc:
            log.warning(
                "Failed to fetch OpenCTI STIX fallback from %s: %s", self.fallback_stix_url, exc
            )
            return None

        objects = bundle.get("objects", [])
        reports = [o for o in objects if o.get("type") == "report"]

        malware_names = [
            str(o.get("name")) for o in objects if o.get("type") == "malware" and o.get("name")
        ]
        actor_names = [
            str(o.get("name"))
            for o in objects
            if o.get("type") in ("threat-actor", "intrusion-set") and o.get("name")
        ]

        stix_techniques: set[str] = set()
        for o in objects:
            if o.get("type") == "attack-pattern":
                for ext in o.get("external_references", []):
                    if ext.get("source_name") == "mitre-attack" and ext.get("external_id"):
                        stix_techniques.add(str(ext.get("external_id")))

        structured_indicators = extract_stix_observables(objects)
        fallback_indicators = [
            f"{cat}: {v}" for cat, vals in structured_indicators.items() for v in vals
        ]

        for rep in reports:
            rep_id = str(rep.get("id") or "").strip()
            if not rep_id or cursor.already_seen(rep_id):
                continue

            name = str(rep.get("name") or "STIX Intelligence Report")
            description = str(rep.get("description") or "")
            published = str(rep.get("published") or datetime.now(UTC).isoformat())

            extracted_tech = set(_TECHNIQUE_RE.findall(description + " " + name))
            techniques = sorted(extracted_tech | stix_techniques) or [
                "T1190",
                "T1059",
            ]

            content = self._format_report(
                name=name,
                description=description,
                published=published,
                actors=actor_names[:4] or ["Threat Cluster"],
                malware=malware_names[:4],
                techniques=techniques,
                indicators=fallback_indicators,
            )

            metadata: dict[str, Any] = {
                "evidence_profile": "procedural_intrusion",
                "report_id": rep_id,
            }
            if structured_indicators:
                metadata["indicators"] = structured_indicators

            return CTIItem(
                content=content,
                source=self.name,
                received_at=datetime.now(UTC),
                identifier=f"opencti-{abs(hash(rep_id)) % 10000000}",
                metadata=metadata,
                title=f"OpenCTI Report: {name}",
                source_url="https://github.com/OpenCTI-Platform",
            )

        return None

    def acknowledge(self, item: CTIItem) -> None:
        rep_id = str(item.metadata.get("report_id") or item.identifier)
        if rep_id:
            cursor = OpenCTICursorState.load(self.cursor_file)
            cursor.advance(rep_id)
            cursor.save(self.cursor_file)

    def _format_report(
        self,
        name: str,
        description: str,
        published: str,
        actors: list[str],
        malware: list[str],
        techniques: list[str],
        indicators: list[str],
    ) -> str:
        lines = [
            f"Title: OpenCTI Threat Intelligence: {name}",
            "Source: OpenCTI Enterprise Cyber Threat Intelligence Platform",
            f"Published: {published}",
            f"Attributed Threat Actors: {', '.join(actors) if actors else 'Unspecified Actor'}",
            f"Associated Malware Families: {', '.join(malware) if malware else 'None identified'}",
            "",
            "Threat Narrative & Analysis:",
            f"{description[:1500] if description else 'Structured STIX 2.1 intelligence package.'}",
            "",
            "Identified Observables & Indicators:",
        ]
        if indicators:
            for ind in indicators[:8]:
                lines.append(f"  - `{ind}`")
        else:
            lines.append("  - Behavioral TTP and procedure tracking")

        lines.extend(
            [
                "",
                f"{ATTACK_TECHNIQUE_LINE} {', '.join(techniques or ['T1059', 'T1105'])}",
            ]
        )
        return "\n".join(lines)
