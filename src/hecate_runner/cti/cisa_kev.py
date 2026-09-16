"""CISA Known Exploited Vulnerabilities (KEV) catalog CTI provider.

Polls the public CISA KEV JSON feed and returns vulnerabilities that have
been added since the last acknowledged cursor date.

Vulnerability-shaped rather than behavior-shaped: generates intelligence focused
on identifying exploitation of a specific CVE rather than a broader TTP.
"""

import json
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hecate_runner.cti.base import CTIItem, CTIProvider

log = logging.getLogger(__name__)

# The authoritative source
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevProvider(CTIProvider):
    """Provides CTI items from the CISA KEV catalog."""

    name: str = "cisa_kev"

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.cursor_file = self.workspace / ".cursors" / "cisa_kev_cursor.json"

        # In-memory cache of the fetched catalog so we don't spam CISA
        self._catalog_cache: list[dict[str, Any]] | None = None

        # Create cursor dir if needed
        self.cursor_file.parent.mkdir(parents=True, exist_ok=True)

    def _read_cursor(self) -> datetime:
        """Return the date of the last processed vulnerability."""
        # With no usable cursor, start roughly a week back rather than
        # ingesting the entire historical catalog.
        fallback = datetime.now(UTC) - timedelta(days=7)
        if not self.cursor_file.exists():
            return fallback

        try:
            data = json.loads(self.cursor_file.read_text(encoding="utf-8"))
            if "last_date_added" in data:
                return datetime.fromisoformat(data["last_date_added"]).replace(tzinfo=UTC)
        except Exception as e:
            log.warning("Failed to parse cisa_kev cursor, starting from 7 days ago: %s", e)

        return fallback

    def _write_cursor(self, date_added: datetime) -> None:
        """Advance the cursor to the given date."""
        try:
            self.cursor_file.write_text(
                json.dumps({"last_date_added": date_added.isoformat()}), encoding="utf-8"
            )
        except Exception as e:
            log.warning("Failed to write cisa_kev cursor: %s", e)

    def _fetch_catalog(self) -> list[dict[str, Any]]:
        """Fetch and parse the KEV catalog."""
        if self._catalog_cache is not None:
            return self._catalog_cache

        try:
            req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "Hecate-Runner/1.0"})
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 200:
                    log.error("CISA KEV request failed: %s", response.status)
                    return []
                data = json.loads(response.read().decode("utf-8"))

                # 'vulnerabilities' is a list of dicts
                vulns: list[dict[str, Any]] = data.get("vulnerabilities", [])

                # Sort by dateAdded ascending so we process oldest first
                vulns.sort(key=lambda v: v.get("dateAdded", ""))

                self._catalog_cache = vulns
                return vulns

        except urllib.error.URLError as e:
            log.error("Failed to connect to CISA KEV: %s", e)
            return []
        except Exception as e:
            log.error("Failed to parse CISA KEV data: %s", e)
            return []

    def _build_blurb(self, vuln: dict[str, Any]) -> str:
        """Render a CISA KEV entry into a markdown CTI blurb."""
        cve = vuln.get("cveID", "Unknown CVE")
        name = vuln.get("vulnerabilityName", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        desc = vuln.get("shortDescription", "")
        date_added = vuln.get("dateAdded", "")
        ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

        lines = [
            f"Title: {vendor} {product} {name} ({cve})",
            "Source: CISA KEV",
            f"Date Added to KEV: {date_added}",
        ]

        if ransomware == "Known":
            lines.append("Tags: ransomware-campaign-use")

        lines.extend(
            [
                "",
                "Summary:",
                f"{cve} is a known exploited vulnerability in {vendor} {product}.",
                desc,
                "",
                "Required Action:",
                vuln.get("requiredAction", "Apply updates per vendor instructions."),
            ]
        )

        return "\n".join(lines)

    def next_item(self) -> CTIItem | None:
        """Return the next unprocessed vulnerability."""
        vulns = self._fetch_catalog()
        if not vulns:
            return None

        cursor = self._read_cursor()

        for vuln in vulns:
            date_str = vuln.get("dateAdded")
            if not date_str:
                continue

            try:
                # KEV dates are YYYY-MM-DD
                date_added = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=UTC)
            except ValueError:
                continue

            if date_added > cursor:
                # We found a new one!
                cve = vuln.get("cveID", "Unknown CVE")
                blurb = self._build_blurb(vuln)

                return CTIItem(
                    content=blurb,
                    source="cisa_kev",
                    received_at=date_added,
                    identifier=cve,
                    metadata={"cve_id": cve},
                    title=f"{vuln.get('vendorProject', '')} {vuln.get('product', '')} {vuln.get('vulnerabilityName', '')}",
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                )

        return None

    def acknowledge(self, item: CTIItem) -> None:
        """Advance the cursor past the acknowledged item."""
        if item.received_at:
            self._write_cursor(item.received_at)
