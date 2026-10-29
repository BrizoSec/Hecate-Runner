"""Living-off-the-land reference entries as deep CTI and bounded enrichment."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from hecate_runner.cti.base import CTIItem
from hecate_runner.cti.github_delta import GitHubDeltaProvider


class CatalogProvider(GitHubDeltaProvider):
    def build_item(self, data: dict[str, Any], raw: str, path: str, revision: str) -> CTIItem:
        name = str(data.get("Name") or data.get("name") or Path(path).stem)
        if self.name == "lolbas":
            commands = data.get("Commands", [])
            if not data.get("Name") or not isinstance(commands, list):
                raise ValueError("invalid LOLBAS command catalog entry")
            platform = "Windows"
        elif self.name == "gtfobins":
            functions = data.get("functions")
            if not isinstance(functions, dict) or not functions:
                raise ValueError("invalid GTFOBins functions entry")
            commands = []
            for function, variants in functions.items():
                if not isinstance(variants, list):
                    continue
                for variant in variants:
                    if not isinstance(variant, dict):
                        continue
                    if variant.get("code"):
                        commands.append({"Command": variant["code"], "Description": function})
                    for context, details in (variant.get("contexts") or {}).items():
                        if isinstance(details, dict) and details.get("code"):
                            commands.append(
                                {
                                    "Command": details["code"],
                                    "Description": f"{function}: {context}",
                                }
                            )
            platform = "Linux"
        else:
            if not isinstance(data.get("KnownVulnerableSamples"), list):
                raise ValueError("invalid LOLDrivers sample catalog entry")
            commands = data.get("Commands") or []
            platform = "Windows"
        if isinstance(commands, dict):
            commands = [commands]
        if not isinstance(commands, list) or any(not isinstance(c, dict) for c in commands):
            raise ValueError("invalid catalog commands")
        artifacts = [
            {
                "value": str(c["Command"]),
                "kind": "command_line",
                "role": "documented abuse example",
                "status": "unknown",
                "evidence": str(c["Command"]),
            }
            for c in commands
            if c.get("Command")
        ]
        hashes = [
            str(sample.get("SHA256") or "")
            for sample in data.get("KnownVulnerableSamples", [])
            if isinstance(sample, dict)
        ]
        techs = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", yaml.safe_dump(data))))
        content = (
            "Documented malicious-use capability catalog; not an observed intrusion. "
            "Hunt for the documented command and privilege/context combination, not the binary name alone. "
            "Placeholders in commands are parameters, never observed IOCs.\n"
            f"Platform: {platform}\nMITRE ATT&CK Techniques: {', '.join(techs)}\n"
            "Parsed command values (YAML scalar decoding only):\n"
            + "\n".join(a["value"] for a in artifacts)
            + "\nVerbatim catalog entry:\n"
            + raw
        )
        return self.item(
            f"{self.name} changed procedure: {name}",
            content,
            path,
            revision,
            evidence_profile="behavior_catalog",
            source_artifacts=artifacts,
            platform=platform,
            catalog_name=name,
            reference_only=True,
            sha256=[v for v in hashes if re.fullmatch("[A-Fa-f0-9]{64}", v)],
        )

    def enrich(self, text: str, limit: int = 3) -> list[dict[str, Any]]:
        """Look up named binaries from a pinned index, without acknowledging CTI."""
        state = self.refresh(self.load())
        tokens = set(re.findall(r"[a-z0-9_-]+", text.lower()))
        matches = []
        for path in state.get("entries", {}):
            if Path(path).stem.lower() not in tokens:
                continue
            raw, data = self.fetch_entry(state["revision"], path)
            item = self.build_item(data, raw, path, state["revision"])
            matches.append(
                {
                    "catalog": self.name,
                    "source_url": item.source_url,
                    "revision": state["revision"],
                    "entry": data,
                    "meaning": "documented capability; not evidence of use in this intrusion",
                }
            )
            if len(matches) >= limit:
                break
        return matches


class LolbasProvider(CatalogProvider):
    name = "lolbas"
    repo = "LOLBAS-Project/LOLBAS"
    branch = "master"
    prefix = "yml/"


class LolDriversProvider(CatalogProvider):
    name = "loldrivers"
    repo = "magicsword-io/LOLDrivers"
    prefix = "yaml/"

    def enrich(self, text: str, limit: int = 3) -> list[dict[str, Any]]:
        # Driver entries have UUID filenames: match their authoritative hash
        # catalog, not UUID stems or guessed binary names.
        import json
        import time

        from hecate_runner.atomic_write import atomic_write_text

        hashes = set(re.findall(r"\b[a-fA-F0-9]{64}\b", text.lower()))
        if not hashes:
            return []
        cache = self.workspace / ".hecate" / "catalogs" / "loldrivers.json"
        if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
            entries = json.loads(cache.read_text())
        else:
            r = self.client.get("https://www.loldrivers.io/api/drivers.json")
            r.raise_for_status()
            if len(r.content) > 30_000_000:
                raise ValueError("driver catalog exceeds size limit")
            entries = r.json()
            if not isinstance(entries, list):
                raise ValueError("invalid driver catalog")
            atomic_write_text(cache, json.dumps(entries))
        import hashlib

        snapshot = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
        return [
            {
                "catalog": self.name,
                "source_url": "https://www.loldrivers.io/api/drivers.json",
                "snapshot_sha256": snapshot,
                "entry": entry,
                "meaning": "catalog-listed driver hash; verify load/signature and context",
            }
            for entry in entries
            if any(
                str(s.get("SHA256", "")).lower() in hashes
                for s in entry.get("KnownVulnerableSamples", [])
                if isinstance(s, dict)
            )
        ][:limit]


class GTFOBinsProvider(CatalogProvider):
    name = "gtfobins"
    repo = "GTFOBins/GTFOBins.github.io"
    branch = "master"
    prefix = "_gtfobins/"
    suffixes = (".yml", ".yaml", ".md", "")

    def relevant(self, path: str) -> bool:
        return path.startswith(self.prefix) and Path(path).suffix in self.suffixes
