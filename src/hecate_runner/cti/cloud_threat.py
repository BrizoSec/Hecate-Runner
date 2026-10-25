"""Cloud Threat Intelligence provider (Permiso P0 Labs, Wiz Research, AWS Bulletins).

Consumes authoritative cloud, identity, and container threat research detailing
real-world adversary campaigns (e.g., LUCR-3, Scattered Spider, GUI-vil, TeamTNT)
abusing cloud IAM roles (AWS STS AssumeRole), Azure Entra ID service principals,
and Kubernetes control planes.
"""

from __future__ import annotations

import html
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import feedparser
import httpx

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

DEFAULT_CLOUD_FEEDS: tuple[str, ...] = (
    "https://permiso.io/blog/rss.xml",
    "https://www.wiz.io/feed/rss.xml",
    "https://aws.amazon.com/security/security-bulletins/feed/",
)

REQUEST_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")

_CLOUD_IAM_PATTERNS = re.compile(
    r"\b(assumerole(?:withwebidentity)?|getsessiontoken|iam:passrole|createrole|addcredential|"
    r"serviceprincipal|consent to application|oauth2permissiongrant|rolemanagement\.readwrite|"
    r"directory\.readwrite|app_role|sts\.amazonaws\.com)\b",
    re.IGNORECASE,
)

_CONTAINER_K8S_PATTERNS = re.compile(
    r"\b(cluster-admin|hostpath|privileged:\s*true|container escape|kubelet|kubectl|"
    r"daemonset|serviceaccount|cgroup|namespaces|docker\.sock|k8s)\b",
    re.IGNORECASE,
)


class CloudThreatError(RuntimeError):
    """Raised when an operation on the Cloud Threat provider fails."""


@dataclass
class CloudThreatCursorState:
    """Track processed cloud threat intelligence feed entry links."""

    seen_links: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> CloudThreatCursorState:
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return cls(seen_links=list(raw.get("seen_links") or []))
        except Exception as exc:
            log.warning("Failed to load Cloud Threat cursor from %s: %s; starting clean", path, exc)
            return cls()

    def advance(self, link: str) -> None:
        if link and link not in self.seen_links:
            self.seen_links.append(link)
            if len(self.seen_links) > 2000:
                self.seen_links = self.seen_links[-2000:]

    def save(self, path: Path) -> None:
        payload = {
            "seen_links": self.seen_links,
            "last_updated": datetime.now(UTC).isoformat(),
        }
        atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True))


class CloudThreatProvider(CTIProvider):
    """Consumes cloud, identity, and container adversary threat feeds."""

    name: str = "cloud_threat"

    def __init__(
        self,
        cursor_file: Path,
        *,
        feed_urls: list[str] | tuple[str, ...] = DEFAULT_CLOUD_FEEDS,
        max_entry_age_days: int = 90,
        request_timeout_sec: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.cursor_file = cursor_file
        self.feed_urls = list(feed_urls)
        self.max_entry_age_days = max_entry_age_days
        self.request_timeout_sec = request_timeout_sec
        self._external_client = client is not None
        self._client = client or httpx.Client(
            timeout=request_timeout_sec,
            headers={
                "User-Agent": REQUEST_USER_AGENT,
                "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
            },
            follow_redirects=True,
        )

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def next_item(self) -> CTIItem | None:
        return self.poll()

    def poll(self) -> CTIItem | None:
        cursor = CloudThreatCursorState.load(self.cursor_file)
        seen_set = set(cursor.seen_links)

        cutoff = datetime.now(UTC) - timedelta(days=self.max_entry_age_days)

        for feed_url in self.feed_urls:
            try:
                xml_content = self._fetch_feed(feed_url)
            except CloudThreatError as exc:
                log.warning("Failed to fetch cloud threat feed %s: %s", feed_url, exc)
                continue

            parsed = feedparser.parse(xml_content)
            for entry in parsed.entries:
                link = str(entry.get("link") or entry.get("id") or "").strip()
                if not link or link in seen_set:
                    continue

                pub_dt = self._parse_published(entry)
                if pub_dt and pub_dt < cutoff:
                    continue

                item = self._entry_to_cti_item(entry, feed_url, pub_dt or datetime.now(UTC))
                if item:
                    log.info(
                        "Cloud Threat provider routed item %s (%s)", item.identifier, item.title
                    )
                    return item

        log.debug("No new unrouted Cloud Threat intelligence items found")
        return None

    def acknowledge(self, item: CTIItem) -> None:
        link = item.metadata.get("link") or item.source_url or item.identifier
        if not link:
            log.warning("Cannot acknowledge cloud threat item without link (%r)", item)
            return
        cursor = CloudThreatCursorState.load(self.cursor_file)
        cursor.advance(str(link))
        cursor.save(self.cursor_file)

    def _fetch_feed(self, url: str) -> str:
        try:
            resp = self._client.get(url)
        except httpx.RequestError as exc:
            raise CloudThreatError(f"HTTP request to {url} failed: {exc}") from exc

        if resp.status_code != 200:
            raise CloudThreatError(f"HTTP {resp.status_code} from {url}")

        return resp.text

    def _parse_published(self, entry: Any) -> datetime | None:
        for attr in ("published_parsed", "updated_parsed", "created_parsed"):
            val = getattr(entry, attr, None) or entry.get(attr)
            if val and len(val) >= 6:
                try:
                    return datetime(val[0], val[1], val[2], val[3], val[4], val[5], tzinfo=UTC)
                except Exception:
                    pass
        return None

    def _entry_to_cti_item(self, entry: Any, feed_url: str, pub_dt: datetime) -> CTIItem | None:
        title = html.unescape(
            str(entry.get("title") or "Cloud Threat Intelligence Advisory").strip()
        )
        link = str(entry.get("link") or "").strip()

        raw_summary = str(entry.get("summary") or entry.get("description") or "")
        content_list = entry.get("content") or []
        if content_list and isinstance(content_list, list) and isinstance(content_list[0], dict):
            raw_summary = content_list[0].get("value") or raw_summary

        clean_text = _HTML_TAG_RE.sub(" ", raw_summary)
        clean_text = html.unescape(re.sub(r"\s+", " ", clean_text)).strip()

        combined_text = f"{title}\n{clean_text}"
        lowered = combined_text.lower()

        # Extract MITRE ATT&CK techniques
        explicit_techniques = _TECHNIQUE_RE.findall(combined_text)
        techniques: set[str] = set(explicit_techniques)

        # Inferred cloud techniques
        if _CLOUD_IAM_PATTERNS.search(combined_text):
            techniques.add("T1078.004")
            techniques.add("T1098.001")
        if _CONTAINER_K8S_PATTERNS.search(combined_text):
            techniques.add("T1610")
            techniques.add("T1611")
        if any(k in lowered for k in ("s3", "blob", "bucket", "exfiltration", "cloud storage")):
            techniques.add("T1530")
        if any(
            k in lowered
            for k in (
                "discovery",
                "reconnaissance",
                "list-users",
                "get-caller-identity",
                "describe",
            )
        ):
            techniques.add("T1580")
        if _CVE_RE.search(combined_text):
            techniques.add("T1190")

        if not techniques:
            techniques.add("T1078.004")

        # Procedural artifact lines
        cves = sorted(set(_CVE_RE.findall(combined_text)))
        iam_actions = sorted(set(m.group(0) for m in _CLOUD_IAM_PATTERNS.finditer(combined_text)))
        k8s_terms = sorted(set(m.group(0) for m in _CONTAINER_K8S_PATTERNS.finditer(combined_text)))

        lines = [
            f"Cloud Threat Intelligence: {title}",
            f"Feed Source: {feed_url}",
        ]
        if cves:
            lines.append(f"Associated CVEs: {', '.join(cves)}")
        if iam_actions:
            lines.append(f"Observed Cloud IAM Operations: {', '.join(iam_actions)}")
        if k8s_terms:
            lines.append(f"Container & Control Plane Telemetry: {', '.join(k8s_terms)}")

        lines.append(f"Executive Summary: {clean_text[:600]}")
        lines.append(f"{ATTACK_TECHNIQUE_LINE}: {', '.join(sorted(techniques))}")

        slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
        identifier = f"cloud-{slug or 'threat'}-{pub_dt.strftime('%Y%m%d')}"

        content = "\n".join(lines)
        metadata = {
            "source": "cloud_threat",
            "feed_url": feed_url,
            "cves": cves,
            "iam_actions": iam_actions,
            "k8s_terms": k8s_terms,
            "link": link,
            "techniques": sorted(techniques),
            "evidence_profile": "cloud_telemetry",
            "indicators": {"cve": cves} if cves else {},
        }

        return CTIItem(
            content=content,
            source=self.name,
            received_at=pub_dt,
            identifier=identifier,
            metadata=metadata,
            title=f"Cloud Threat Intel: {title}",
            source_url=link,
        )
