"""New/changed Nuclei HTTP templates gated by live KEV or FIRST EPSS risk.

Templates are reference procedures only. No scanner, DSL, payload expansion,
code, interactsh callback or HTTP request from a template is executed.
"""

from __future__ import annotations

import re
import time
from datetime import UTC, date, datetime
from typing import Any

from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.github_delta import GitHubDeltaProvider


class NucleiProvider(GitHubDeltaProvider):
    name = "nuclei"
    repo = "projectdiscovery/nuclei-templates"
    prefix = "http/cves/"

    def __init__(
        self, *args: Any, min_epss: float = 0.5, min_percentile: float = 0.85, **kwargs: Any
    ):
        super().__init__(*args, **kwargs)
        self.min_epss, self.min_percentile = min_epss, min_percentile
        self._kev: set[str] | None = None

    def eligible(self, cves: list[str]) -> tuple[bool, str]:
        # Embedded template EPSS/tags may be old; they cannot authorize intake.
        if self._kev is None:
            r = self.client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            r.raise_for_status()
            self._kev = {str(v["cveID"]).upper() for v in r.json()["vulnerabilities"]}
        if any(cve in self._kev for cve in cves):
            return True, "CISA KEV"
        r = self.client.get("https://api.first.org/data/v1/epss", params={"cve": ",".join(cves)})
        r.raise_for_status()
        data = r.json()["data"]
        for value in data:
            observed = date.fromisoformat(str(value.get("date", "")))
            age = (datetime.now(UTC).date() - observed).days
            if not 0 <= age <= 3:
                raise ValueError("stale or future EPSS response; retain template for retry")
            score = float(value.get("epss", 0))
            percentile = float(value.get("percentile", 0))
            if not (0 <= score <= 1 and 0 <= percentile <= 1):
                raise ValueError("invalid EPSS probability")
            if (
                value.get("cve") in cves
                and score >= self.min_epss
                and percentile >= self.min_percentile
            ):
                return (
                    True,
                    f"FIRST EPSS {value['epss']} percentile {value['percentile']} dated {value.get('date', 'unknown')}",
                )
        return False, "below risk threshold"

    def build_item(
        self, data: dict[str, Any], raw: str, path: str, revision: str
    ) -> CTIItem | None:
        info = data.get("info", {})
        classification = info.get("classification", {})
        cves = sorted(
            set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", str(classification.get("cve-id", "")), re.I))
        )
        cves = [c.upper() for c in cves]
        if (
            not cves
            or not data.get("http")
            or any(k in data for k in ("code", "javascript", "headless"))
        ):
            self.reject(path, revision, "requires an explicit CVE and HTTP-only template")
            return None
        allowed, reason = self.eligible(cves)
        if not allowed:
            self.reject(path, revision, reason)
            return None
        requests = []
        for req in data["http"]:
            if not isinstance(req, dict):
                raise ValueError("invalid HTTP template")
            # Preserve exact, unevaluated source strings and response matchers.
            requests.append(
                {
                    k: req[k]
                    for k in (
                        "method",
                        "path",
                        "headers",
                        "body",
                        "raw",
                        "matchers",
                        "matchers-condition",
                        "extractors",
                    )
                    if k in req
                }
            )
        from hecate_runner.cti.reference_rules import template_requests

        literals = [
            {
                "value": f"{req['method']} {req['uri']}",
                "kind": "http_request",
                "role": "documented request example",
                "status": "unknown",
                "evidence": f"Documented probe request: {req['method']} {req['uri']}",
            }
            for req in template_requests(requests)
        ]
        text = (
            "Documented vulnerability probe, not an observed intrusion or evidence that this CVE was exploited here. "
            "Request fields are verbatim template definitions; response matchers are not request/WAF fields. "
            "Unresolved variables/DSL require analyst mapping; do not invent their values.\n"
            f"Risk gate: {reason}\nCVEs: {', '.join(cves)}\nParsed request projections:\n"
            + "\n".join(a["evidence"] for a in literals)
            + f"\nHTTP template:\n{raw}"
        )
        return self.item(
            f"Nuclei template: {data.get('id', path)} - {info.get('name', '')}",
            text,
            path,
            revision,
            evidence_profile="vulnerability_template",
            reference_only=True,
            cves=cves,
            risk_basis=reason,
            risk_checked_at=time.time(),
            http_requests=requests,
            source_artifacts=literals,
            structured_document=data,
        )
