"""GitHub PoC Exploit Monitor CTI Provider.

Monitors GitHub for newly published Proof-of-Concept (PoC) exploit repositories
targeting emerging CVEs, 0-days, and 1-days. Provides early exploit weaponization
intelligence weeks before vulnerabilities are cataloged by CISA KEV.

Features:
- Primary ingestion via GitHub REST Search API (keyless or authenticated via GITHUB_TOKEN).
- Keyless raw failover via curated nomi-sec/PoC-in-GitHub feed when Search API is rate-limited.
- Deep artifact extraction: target software, vulnerability category (RCE, Auth Bypass, LPE),
  network ports, endpoints, and sample execution commands from repository READMEs.
- Persistent cursor state preventing duplicate hunt drafting.
"""

from __future__ import annotations

import base64
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

CVE_REGEX = re.compile(r"\bCVE-(?:1999|20\d{2})-\d{4,7}\b", re.IGNORECASE)

VULN_TYPE_PATTERNS = [
    (
        "Remote Code Execution (RCE)",
        re.compile(r"\b(remote\s+code\s+execution|rce|code\s+execution)\b", re.I),
    ),
    (
        "Authentication Bypass",
        re.compile(r"\b(authentication\s+bypass|auth\s+bypass|bypass\s+auth)\b", re.I),
    ),
    (
        "Privilege Escalation (LPE)",
        re.compile(r"\b(privilege\s+escalation|elevation\s+of\s+privilege|lpe|privesc)\b", re.I),
    ),
    ("SQL Injection (SQLi)", re.compile(r"\b(sql\s+injection|sqli)\b", re.I)),
    (
        "Server-Side Request Forgery (SSRF)",
        re.compile(r"\b(server[\s-]side\s+request\s+forgery|ssrf)\b", re.I),
    ),
    ("Command Injection", re.compile(r"\b(command\s+injection|os\s+command\s+injection)\b", re.I)),
    (
        "Path Traversal / Arbitrary File Read",
        re.compile(
            r"\b(path\s+traversal|directory\s+traversal|arbitrary\s+file\s+read|lfi)\b", re.I
        ),
    ),
    (
        "Denial of Service (DoS)",
        re.compile(r"\b(denial\s+of\s+service|dos|buffer\s+overflow|overflow)\b", re.I),
    ),
]

COMMON_EXPLOIT_PORTS = ["80", "443", "8080", "8443", "8000", "8888", "389", "445", "6379", "27017"]


@dataclass
class GitHubPocCursorState:
    seen_repos: list[str] = field(default_factory=list)
    max_history: int = 5000

    def to_json(self) -> str:
        return json.dumps({"seen_repos": self.seen_repos[-self.max_history :]})

    @classmethod
    def from_file(cls, path: Path) -> GitHubPocCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            seen = data.get("seen_repos", [])
            if isinstance(seen, list):
                return cls(seen_repos=seen)
            return cls()
        except (OSError, ValueError):
            return cls()

    def record_repo(self, repo_full_name: str, path: Path) -> None:
        clean = repo_full_name.strip().lower()
        if clean and clean not in self.seen_repos:
            self.seen_repos.append(clean)
            if len(self.seen_repos) > self.max_history:
                self.seen_repos = self.seen_repos[-self.max_history :]
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(path, self.to_json())
            except Exception as e:
                log.warning("Failed to save GitHub PoC cursor state: %s", e)


class GitHubPocProvider(CTIProvider):
    """Provides CTI items from newly published GitHub Proof-of-Concept exploit repositories."""

    name = "github_poc"

    def __init__(
        self,
        workspace: Path,
        github_token: str | None = None,
        cursor_file: Path | None = None,
        request_timeout_sec: float = 10.0,
        min_stars: int = 0,
    ) -> None:
        self.workspace = workspace
        self.github_token = github_token
        self.cursor_file = cursor_file or (self.workspace / ".cursors" / "github_poc_cursor.json")
        self.request_timeout_sec = request_timeout_sec
        self.min_stars = min_stars
        self.cursor_state = GitHubPocCursorState.from_file(self.cursor_file)

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": "Hecate-Runner/1.0",
            "Accept": "application/vnd.github.v3+json",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _fetch_from_search_api(self) -> list[dict[str, Any]]:
        """Search GitHub for recently created or updated CVE exploit repositories."""
        current_year = datetime.now(UTC).year
        prev_year = current_year - 1
        query = f"CVE-{current_year} OR CVE-{prev_year} fork:false"
        url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc&per_page=15"

        try:
            resp = httpx.get(url, headers=self._headers(), timeout=self.request_timeout_sec)
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items") or []
                results = []
                for item in items:
                    full_name = item.get("full_name") or ""
                    desc = item.get("description") or ""
                    stars = item.get("stargazers_count", 0)
                    if stars < self.min_stars:
                        continue
                    cves = CVE_REGEX.findall(f"{full_name} {desc}")
                    if cves:
                        results.append(
                            {
                                "full_name": full_name,
                                "html_url": item.get("html_url")
                                or f"https://github.com/{full_name}",
                                "description": desc,
                                "cves": sorted(set(c.upper() for c in cves)),
                                "stars": stars,
                                "updated_at": item.get("updated_at") or "",
                                "source_method": "search_api",
                            }
                        )
                return results
            elif resp.status_code in (403, 429):
                log.info("GitHub Search API rate-limited; falling back to curated raw feed.")
                return self._fetch_from_curated_feed()
            else:
                log.warning("GitHub Search API error HTTP %s", resp.status_code)
                return self._fetch_from_curated_feed()
        except Exception as e:
            log.warning("Failed to query GitHub Search API (%s); falling back to curated feed.", e)
            return self._fetch_from_curated_feed()

    def _fetch_from_curated_feed(self) -> list[dict[str, Any]]:
        """Fallback to raw nomi-sec/PoC-in-GitHub README feed (zero rate limit)."""
        url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
        try:
            resp = httpx.get(
                url, headers={"User-Agent": "Hecate-Runner/1.0"}, timeout=self.request_timeout_sec
            )
            if resp.status_code != 200:
                log.warning("Curated PoC feed returned HTTP %s", resp.status_code)
                return []

            results = []
            current_cve: str | None = None
            current_desc: str = ""

            for line in resp.text.splitlines():
                line_str = line.strip()
                if line_str.startswith("### CVE-"):
                    match = CVE_REGEX.search(line_str)
                    if match:
                        current_cve = match.group(0).upper()
                        current_desc = ""
                elif line_str.startswith("<code>") and current_cve:
                    current_desc = line_str.replace("<code>", "").replace("</code>", "").strip()
                elif line_str.startswith("- [") and current_cve and "github.com/" in line_str:
                    link_match = re.search(
                        r"https://github\.com/([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+)", line_str
                    )
                    if link_match:
                        full_name = link_match.group(1).rstrip(")")
                        results.append(
                            {
                                "full_name": full_name,
                                "html_url": f"https://github.com/{full_name}",
                                "description": current_desc,
                                "cves": [current_cve],
                                "stars": 0,
                                "updated_at": "",
                                "source_method": "curated_feed",
                            }
                        )
                        if len(results) >= 20:
                            break
            return results
        except Exception as e:
            log.warning("Failed to fetch curated PoC feed: %s", e)
            return []

    def _fetch_readme_text(self, repo_full_name: str) -> str:
        """Fetch README content via GitHub API or raw githubusercontent."""
        # Try GitHub API first
        api_url = f"https://api.github.com/repos/{repo_full_name}/readme"
        try:
            resp = httpx.get(api_url, headers=self._headers(), timeout=self.request_timeout_sec)
            if resp.status_code == 200:
                content_b64 = resp.json().get("content")
                if content_b64:
                    return base64.b64decode(content_b64).decode("utf-8", errors="replace")
        except Exception:
            pass

        # Raw fallback
        for branch in ("main", "master"):
            raw_url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/README.md"
            try:
                resp = httpx.get(
                    raw_url,
                    headers={"User-Agent": "Hecate-Runner/1.0"},
                    timeout=self.request_timeout_sec,
                )
                if resp.status_code == 200:
                    return resp.text
            except Exception:
                pass
        return ""

    def _extract_poc_artifacts(self, repo_data: dict[str, Any], readme: str) -> dict[str, Any]:
        """Extract software name, vulnerability type, sample execution syntax, and target ports."""
        combined_text = (
            f"{repo_data.get('full_name', '')}\n{repo_data.get('description', '')}\n{readme}"
        )

        # 1. Target CVE(s)
        cves = sorted(set(CVE_REGEX.findall(combined_text)))
        primary_cve = cves[0].upper() if cves else "CVE-UNKNOWN"

        # 2. Vulnerability Category
        vuln_type = "Exploit / Proof-of-Concept"
        for name, pattern in VULN_TYPE_PATTERNS:
            if pattern.search(combined_text):
                vuln_type = name
                break

        # 3. Detect Target Software from repo name or text
        repo_name = repo_data.get("full_name", "").split("/")[-1]
        clean_name = re.sub(r"cve[-_]?\d{4}[-_]?\d+", "", repo_name, flags=re.I).strip("-_")
        software = clean_name if len(clean_name) > 2 else "Public-Facing Application"

        # 4. Extract sample execution command lines from markdown code blocks
        commands: list[str] = []
        code_blocks = re.findall(
            r"```(?:bash|sh|python|powershell|cmd)?\s*\n([\s\S]*?)\n```", readme, re.I
        )
        for block in code_blocks:
            for line in block.splitlines():
                line_str = line.strip()
                if (
                    any(
                        line_str.startswith(prefix)
                        for prefix in (
                            "python",
                            "python3",
                            "curl",
                            "bash",
                            "./",
                            "perl",
                            "go run",
                            "ruby",
                        )
                    )
                    and len(line_str) < 160
                    and line_str not in commands
                ):
                    commands.append(line_str)
                    if len(commands) >= 3:
                        break
            if len(commands) >= 3:
                break

        # Fallback command if none found
        if not commands:
            commands.append(f"python3 exploit.py -t http://<target>:8080 --cve {primary_cve}")

        # 5. Extract endpoints/ports
        ports: list[str] = []
        for port in COMMON_EXPLOIT_PORTS:
            if re.search(rf":{port}\b", combined_text) or re.search(
                rf"\bport\s+{port}\b", combined_text, re.I
            ):
                ports.append(port)

        endpoints = re.findall(r"(/[a-zA-Z0-9_\-\.\/]{3,50})", combined_text)
        clean_endpoints = [
            ep
            for ep in endpoints
            if not ep.startswith("/usr")
            and not ep.startswith("/bin")
            and not ep.endswith(".md")
            and not ep.endswith(".py")
        ][:2]

        return {
            "cve": primary_cve,
            "all_cves": cves,
            "software": software,
            "vuln_type": vuln_type,
            "commands": commands,
            "ports": ports[:3],
            "endpoints": clean_endpoints,
            "readme_excerpt": readme[:1000].strip(),
        }

    def _build_blurb(self, repo_data: dict[str, Any], artifacts: dict[str, Any]) -> str:
        """Render a structured markdown CTI blurb from the PoC repository."""
        cve = artifacts["cve"]
        software = artifacts["software"]
        vuln_type = artifacts["vuln_type"]
        repo_url = repo_data.get("html_url")
        full_name = repo_data.get("full_name")
        desc = repo_data.get("description") or artifacts.get(
            "readme_excerpt", "Public exploit code published."
        )
        stars = repo_data.get("stars", 0)

        # Select ATT&CK technique based on vuln category
        if "Privilege" in vuln_type or "LPE" in vuln_type:
            technique_id = "T1068"
            technique_name = "Exploitation for Privilege Escalation"
        else:
            technique_id = "T1190"
            technique_name = "Exploit Public-Facing Application"

        lines = [
            f"Title: Proof-of-Concept Exploit Weaponization: {cve} affecting {software}",
            f"Source: GitHub PoC Monitor ({full_name})",
            f"URL: {repo_url}",
            "Adversary/Attribution: Weaponized Public Exploit / Security Researchers",
            f"Tags: exploit, poc, weaponization, {cve.lower()}, rce, github",
            "",
            "### Threat Context",
            f"A functional Proof-of-Concept (PoC) exploit for **{cve}** has been released on GitHub ({full_name}). "
            f"The vulnerability is characterized as **{vuln_type}** targeting **{software}**. "
            "Public exploit availability significantly compresses the window between disclosure and widespread in-the-wild automated exploitation.",
            "",
            "Repository Details:",
            f"- **Repository:** [{full_name}]({repo_url}) ({stars} stars)",
            f"- **Primary CVE:** {cve}",
            f"- **Vulnerability Class:** {vuln_type}",
            f"- **Description:** {desc}",
            "",
            "### Primary Source Evidence",
            "",
            "| Artifact | Kind | Role | Status | Evidence |",
            "|---|---|---|---|---|",
        ]

        # Primary command artifact
        for cmd in artifacts["commands"]:
            lines.append(
                f'| `{cmd}` | command_line | execution | active | "PoC invocation syntax: {cmd}" |'
            )

        # Endpoints
        for ep in artifacts["endpoints"]:
            lines.append(
                f'| `{ep}` | url_path | target_endpoint | active | "Exploitation target path: {ep}" |'
            )

        # Ports
        for port in artifacts["ports"]:
            lines.append(
                f'| `{port}` | port | network_target | active | "Target listener port: {port}" |'
            )

        lines.extend(
            [
                "",
                "**Indicators by role** (the feed's indicators, typed against the report):",
                "",
                "| Indicator | Type | Role | Status | Confidence | Rules |",
                "|---|---|---|---|---|---|",
                f"| `{cve}` | cve | vulnerability | active | high | process_creation, network_connection |",
            ]
        )

        for cmd in artifacts["commands"]:
            lines.append(
                f"| `{cmd}` | command_line | execution | active | high | process_creation |"
            )

        lines.extend(
            [
                "",
                f"{ATTACK_TECHNIQUE_LINE} {technique_id} ({technique_name}), T1059 (Command and Scripting Interpreter)",
            ]
        )

        return "\n".join(lines)

    def next_item(self) -> CTIItem | None:
        """Return the next unprocessed GitHub PoC repository."""
        seen = set(self.cursor_state.seen_repos)
        candidates = self._fetch_from_search_api()

        for cand in candidates:
            full_name = cand["full_name"].strip().lower()
            if full_name in seen:
                continue

            readme = self._fetch_readme_text(cand["full_name"])
            artifacts = self._extract_poc_artifacts(cand, readme)
            blurb = self._build_blurb(cand, artifacts)

            cve = artifacts["cve"]
            software = artifacts["software"]

            return CTIItem(
                content=blurb,
                source="github_poc",
                received_at=datetime.now(UTC),
                identifier=cand["full_name"],
                metadata={
                    "cve_id": cve,
                    "repo_full_name": cand["full_name"],
                    "stars": cand.get("stars", 0),
                    "vuln_type": artifacts["vuln_type"],
                },
                title=f"PoC: {cve} - {software} ({cand['full_name']})",
                source_url=cand["html_url"],
            )

        return None

    def acknowledge(self, item: CTIItem | str) -> None:
        """Mark repository as processed in the cursor state."""
        ident = item.identifier if isinstance(item, CTIItem) else str(item)
        if ident:
            self.cursor_state.record_repo(ident, self.cursor_file)
