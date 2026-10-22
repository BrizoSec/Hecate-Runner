"""VX-Underground CTI provider for new malware strains and research publications.

Ingests newly cataloged malware families, leaked source code, and analysis papers
from official VX-Underground repositories (vxunderground/MalwareSourceCode and
vxunderground/VXUG-Papers):
- Dual mode intake: Uses GitHub REST API if GITHUB_TOKEN is available;
  seamlessly falls back to public Atom feeds and commit patches with zero rate limit.
- Extracts platform/language (Windows, Linux, MacOS, Android, Python), category
  (Stealer, Ransomware, Keylogger, Botnet, Rootkit, Backdoor), malware family name,
  archive names, and git blob hashes.
- Emits structured Primary Source Evidence and Indicators by Role tables with
  appropriate MITRE ATT&CK techniques (T1555, T1005, T1486, T1056, T1059, T1204).
- Maintains persistent cursor in .cursors/vxunderground_cursor.json.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider

log = logging.getLogger(__name__)

ATOM_REPOS = [
    {
        "name": "MalwareSourceCode",
        "repo": "vxunderground/MalwareSourceCode",
        "atom_url": "https://github.com/vxunderground/MalwareSourceCode/commits.atom",
        "api_commits_url": "https://api.github.com/repos/vxunderground/MalwareSourceCode/commits?per_page=15",
    },
    {
        "name": "VXUG-Papers",
        "repo": "vxunderground/VXUG-Papers",
        "atom_url": "https://github.com/vxunderground/VXUG-Papers/commits.atom",
        "api_commits_url": "https://api.github.com/repos/vxunderground/VXUG-Papers/commits?per_page=15",
    },
]

MALWARE_CATEGORY_TECHNIQUES: dict[str, list[tuple[str, str]]] = {
    "stealer": [("T1555", "Credentials from Password Stores"), ("T1005", "Data from Local System")],
    "infostealer": [
        ("T1555", "Credentials from Password Stores"),
        ("T1005", "Data from Local System"),
    ],
    "ransomware": [("T1486", "Data Encrypted for Impact"), ("T1490", "Inhibit System Recovery")],
    "keylogger": [("T1056.001", "Keylogging"), ("T1005", "Data from Local System")],
    "botnet": [("T1071", "Application Layer Protocol"), ("T1498", "Network Denial of Service")],
    "rootkit": [("T1014", "Rootkit"), ("T1574", "Hijack Execution Flow")],
    "backdoor": [
        ("T1059", "Command and Scripting Interpreter"),
        ("T1071", "Application Layer Protocol"),
    ],
    "trojan": [("T1204.002", "Malicious File"), ("T1055", "Process Injection")],
    "miner": [("T1496", "Resource Hijacking")],
    "dropper": [("T1105", "Ingress Tool Transfer"), ("T1055", "Process Injection")],
    "loader": [("T1055", "Process Injection"), ("T1105", "Ingress Tool Transfer")],
}


@dataclass
class VxUndergroundCursorState:
    """Tracks seen VX-Underground commit SHAs to prevent duplicate ingestion."""

    seen_commits: list[str] = field(default_factory=list)
    max_history: int = 500

    def to_json(self) -> str:
        return json.dumps({"seen_commits": self.seen_commits}, indent=2)

    @classmethod
    def from_file(cls, path: Path) -> VxUndergroundCursorState:
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            seen = data.get("seen_commits", [])
            if isinstance(seen, list):
                return cls(seen_commits=[str(s).strip().lower() for s in seen if s])
            return cls()
        except (OSError, ValueError, TypeError) as e:
            log.warning("Failed to load VX-Underground cursor from %s: %s", path, e)
            return cls()

    def record_commit(self, commit_sha: str, path: Path) -> None:
        clean = commit_sha.strip().lower()
        if clean and clean not in self.seen_commits:
            self.seen_commits.append(clean)
            if len(self.seen_commits) > self.max_history:
                self.seen_commits = self.seen_commits[-self.max_history :]
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_text(path, self.to_json())
            except Exception as e:
                log.warning("Failed to save VX-Underground cursor state: %s", e)


class VxUndergroundProvider(CTIProvider):
    """Provides CTI items from VX-Underground malware releases and research papers."""

    name = "vxunderground"

    def __init__(
        self,
        workspace: Path,
        github_token: str | None = None,
        cursor_file: Path | None = None,
        request_timeout_sec: float = 15.0,
    ) -> None:
        self.workspace = workspace
        self.github_token = github_token.strip() if github_token and github_token.strip() else None
        self.cursor_file = cursor_file or (workspace / ".cursors" / "vxunderground_cursor.json")
        self.request_timeout_sec = request_timeout_sec
        self.cursor_state = VxUndergroundCursorState.from_file(self.cursor_file)

    def _fetch_from_api(self, repo_info: dict[str, str]) -> list[dict[str, Any]]:
        """Fetch commits via GitHub REST API if token available."""
        if not self.github_token:
            return []

        url = repo_info["api_commits_url"]
        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "User-Agent": "Hecate-Agent/1.0",
            "Accept": "application/vnd.github.v3+json",
        }
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=self.request_timeout_sec) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
                commits: list[dict[str, Any]] = []
                for c in data:
                    sha = c.get("sha", "")
                    commit_obj = c.get("commit", {})
                    msg = commit_obj.get("message", "").split("\n")[0].strip()
                    date_str = (
                        commit_obj.get("author", {}).get("date") or datetime.now(UTC).isoformat()
                    )
                    html_url = (
                        c.get("html_url") or f"https://github.com/{repo_info['repo']}/commit/{sha}"
                    )
                    commits.append(
                        {
                            "sha": sha,
                            "title": msg,
                            "date": date_str,
                            "html_url": html_url,
                            "repo": repo_info["repo"],
                            "repo_name": repo_info["name"],
                        }
                    )
                return commits
        except Exception as e:
            log.warning(
                "GitHub API fetch failed for %s: %s; falling back to Atom feed",
                repo_info["repo"],
                e,
            )
            return []

    def _fetch_from_atom(self, repo_info: dict[str, str]) -> list[dict[str, Any]]:
        """Fetch latest commits from GitHub public Atom feed with zero rate limits."""
        url = repo_info["atom_url"]
        headers = {"User-Agent": "Hecate-Agent/1.0"}
        req = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=self.request_timeout_sec) as resp:
                xml_data = resp.read()
                tree = ET.fromstring(xml_data)
                ns = {"atom": "http://www.w3.org/2005/Atom"}
                commits: list[dict[str, Any]] = []

                for entry in tree.findall("atom:entry", ns):
                    title_elem = entry.find("atom:title", ns)
                    title = (
                        title_elem.text.strip()
                        if title_elem is not None and title_elem.text
                        else ""
                    )
                    updated_elem = entry.find("atom:updated", ns)
                    updated = (
                        updated_elem.text.strip()
                        if updated_elem is not None and updated_elem.text
                        else ""
                    )
                    link_elem = entry.find("atom:link", ns)
                    link = link_elem.attrib.get("href", "") if link_elem is not None else ""

                    # Extract commit SHA from URL or entry ID
                    sha = ""
                    if "/commit/" in link:
                        sha = link.split("/commit/")[-1].strip()
                    elif (id_elem := entry.find("atom:id", ns)) is not None:
                        id_text = id_elem.text or ""
                        if "/" in id_text:
                            sha = id_text.split("/")[-1].strip()

                    if sha:
                        commits.append(
                            {
                                "sha": sha,
                                "title": title,
                                "date": updated,
                                "html_url": link,
                                "repo": repo_info["repo"],
                                "repo_name": repo_info["name"],
                            }
                        )
                return commits
        except Exception as e:
            log.warning("Atom feed fetch failed for %s: %s", repo_info["repo"], e)
            return []

    def _fetch_commit_details(self, commit_url: str) -> dict[str, Any]:
        """Fetch the commit patch to extract modified files, platform, and hash."""
        patch_url = f"{commit_url}.patch"
        headers = {"User-Agent": "Hecate-Agent/1.0"}
        req = urllib.request.Request(patch_url, headers=headers)

        details: dict[str, Any] = {
            "files": [],
            "platforms": [],
            "blob_hashes": [],
            "malware_names": [],
        }

        try:
            with urllib.request.urlopen(req, timeout=self.request_timeout_sec) as resp:
                patch_text = resp.read().decode("utf-8", errors="replace")

                # Match diff --git a/path b/path
                file_matches = re.findall(r"diff --git a/(.+?) b/", patch_text)
                for f in file_matches:
                    details["files"].append(f)
                    parts = f.split("/")
                    if len(parts) > 1:
                        details["platforms"].append(parts[0])
                        filename = parts[-1]
                        # Remove extensions like .7z, .zip, .tar.gz, .cpp, .py
                        base_name = re.sub(
                            r"\.(7z|zip|tar\.gz|cpp|c|py|bin|exe|dll)$", "", filename
                        )
                        details["malware_names"].append(base_name)
                    else:
                        details["malware_names"].append(f)

                # Match blob hashes index 00000..sha
                index_matches = re.findall(r"index [0-9a-fA-F]+\.\.([0-9a-fA-F]+)", patch_text)
                for b in index_matches:
                    if b != "0000000":
                        details["blob_hashes"].append(b)

        except Exception as e:
            log.debug("Failed to fetch patch for %s: %s", commit_url, e)

        return details

    def _infer_attack_techniques(self, sample_name: str, platform: str) -> list[tuple[str, str]]:
        """Map sample keywords to MITRE ATT&CK techniques."""
        techniques: list[tuple[str, str]] = []
        name_lower = sample_name.lower()

        for category, mappings in MALWARE_CATEGORY_TECHNIQUES.items():
            if category in name_lower:
                techniques.extend(mappings)

        plat_lower = platform.lower()
        if plat_lower in ("macos", "darwin"):
            techniques.append(("T1204.002", "Malicious File"))
            if ("T1059.004", "Unix Shell") not in [(t[0], t[1]) for t in techniques]:
                techniques.append(("T1059.004", "Unix Shell"))
        elif plat_lower in ("linux", "unix"):
            techniques.append(("T1059.004", "Unix Shell"))
            techniques.append(("T1204.002", "Malicious File"))
        elif plat_lower in ("windows",):
            techniques.append(("T1204.002", "Malicious File"))
            techniques.append(("T1055", "Process Injection"))
        elif plat_lower in ("python", "perl", "ruby"):
            techniques.append(("T1059", "Command and Scripting Interpreter"))

        if not techniques:
            techniques.append(("T1204.002", "Malicious File"))
            techniques.append(("T1027", "Obfuscated Files or Information"))

        # Deduplicate
        seen = set()
        deduped = []
        for tid, name in techniques:
            if tid not in seen:
                seen.add(tid)
                deduped.append((tid, name))
        return deduped

    def _build_blurb(self, commit: dict[str, Any], details: dict[str, Any]) -> str:
        """Format structured threat intelligence blurb for the VX-Underground release."""
        title = commit.get("title", "Malware Artifact Release")
        sha = commit.get("sha", "")
        repo_name = commit.get("repo_name", "MalwareSourceCode")
        repo_url = commit.get(
            "html_url", f"https://github.com/{commit.get('repo', 'vxunderground')}/commit/{sha}"
        )
        date_str = commit.get("date", datetime.now(UTC).isoformat())

        files = details.get("files") or [title]
        platforms = list(dict.fromkeys(details.get("platforms") or []))
        platform_str = ", ".join(platforms) if platforms else "Cross-Platform"
        malware_names = list(dict.fromkeys(details.get("malware_names") or []))
        sample_name = malware_names[0] if malware_names else title

        # Extract category keyword
        category = "Malware Sample"
        for cat in MALWARE_CATEGORY_TECHNIQUES:
            if cat in sample_name.lower():
                category = cat.capitalize()
                break

        techniques = self._infer_attack_techniques(sample_name, platform_str)
        attack_str = ", ".join(f"{tid} ({tname})" for tid, tname in techniques)

        lines = [
            f"Title: VX-Underground Intelligence: {sample_name} ({platform_str})",
            f"Source: VX-Underground ({repo_name})",
            f"URL: {repo_url}",
            f"Adversary/Attribution: {sample_name} Threat Strains",
            f"Tags: vxunderground, malware, {category.lower()}, {platform_str.lower()}, reverse-engineering",
            "",
            "### Threat Context",
            f"A newly cataloged malware family artifact or research paper for **{sample_name}** has been released by VX-Underground ({repo_name}).",
            f"The release provides analyzed source code or payload archives targeting **{platform_str}** environments.",
            "",
            "Repository Artifacts:",
            f"- **Target Strain / Component:** {sample_name}",
            f"- **Target Platform / Environment:** {platform_str}",
            f"- **Repository:** [{commit.get('repo')}](https://github.com/{commit.get('repo')})",
            f"- **Commit SHA:** `{sha}`",
            f"- **Publication Date:** {date_str}",
            f"- **Commit Message:** {title}",
            "",
            "### Primary Source Evidence",
            "",
            "| Artifact | Kind | Role | Status | Evidence |",
            "|---|---|---|---|---|",
            f'| `{sample_name}` | malware_family | attribution | active | "Cataloged malware family on VX-Underground" |',
            f'| `{files[0]}` | file_path | artifact | active | "Repository path in vxunderground: {files[0]}" |',
        ]

        blob_hashes = details.get("blob_hashes") or []
        for b in blob_hashes[:2]:
            lines.append(
                f'| `{b}` | git_blob | payload | active | "Git blob hash for released sample archive" |'
            )

        lines.extend(
            [
                "",
                "**Indicators by role** (the feed's indicators, typed against the report):",
                "",
                "| Indicator | Type | Role | Status | Confidence | Rules |",
                "|---|---|---|---|---|---|",
                f"| `{files[0]}` | filename | artifact | active | high | process_creation, file_event |",
            ]
        )

        for b in blob_hashes[:2]:
            lines.append(f"| `{b}` | sha1 | payload | active | medium | file_event |")

        lines.extend(
            [
                "",
                f"{ATTACK_TECHNIQUE_LINE} {attack_str}",
            ]
        )

        return "\n".join(lines)

    def next_item(self) -> CTIItem | None:
        """Fetch the next unprocessed high-signal malware release from VX-Underground."""
        for repo_info in ATOM_REPOS:
            commits = self._fetch_from_api(repo_info)
            if not commits:
                commits = self._fetch_from_atom(repo_info)

            for commit in commits:
                sha = commit.get("sha", "").strip().lower()
                if not sha or sha in self.cursor_state.seen_commits:
                    continue

                details = self._fetch_commit_details(commit["html_url"])
                blurb = self._build_blurb(commit, details)

                malware_names = details.get("malware_names") or []
                sample_name = malware_names[0] if malware_names else commit.get("title", sha[:8])
                platforms = details.get("platforms") or []
                platform_str = platforms[0] if platforms else "Cross-Platform"

                return CTIItem(
                    content=blurb,
                    source="vxunderground",
                    received_at=datetime.now(UTC),
                    identifier=sha,
                    metadata={
                        "commit_sha": sha,
                        "repo": commit.get("repo"),
                        "sample_name": sample_name,
                        "platform": platform_str,
                        "files": details.get("files", []),
                    },
                    title=f"VX-Underground: {sample_name} ({platform_str})",
                    source_url=commit["html_url"],
                )

        return None

    def acknowledge(self, item: CTIItem | str) -> None:
        """Mark commit SHA as processed in cursor state."""
        ident = item.identifier if isinstance(item, CTIItem) else str(item)
        if ident:
            self.cursor_state.record_commit(ident, self.cursor_file)
