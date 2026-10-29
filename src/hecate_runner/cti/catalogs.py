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

    max_catalog_bytes = 64_000_000

    def enrich(self, text: str, limit: int = 3) -> list[dict[str, Any]]:
        # UUID filenames cannot be matched to binaries. The public JSON includes
        # large PE metadata, so stream with a hard bound and cache only evidence
        # needed for hash correlation, plus the original response digest.
        import hashlib
        import json
        import time

        from hecate_runner.atomic_write import atomic_write_text

        hashes = set(re.findall(r"\b[a-fA-F0-9]{64}\b", text.lower()))
        if not hashes:
            return []
        cache = self.workspace / ".hecate" / "catalogs" / "loldrivers.json"
        if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
            cached = json.loads(cache.read_text())
            entries = cached["entries"]
            snapshot = cached["snapshot_sha256"]
        else:
            payload = bytearray()
            with self.client.stream(
                "GET", "https://www.loldrivers.io/api/drivers.json"
            ) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    if len(payload) + len(chunk) > self.max_catalog_bytes:
                        raise ValueError("driver catalog exceeds size limit; prior cache retained")
                    payload.extend(chunk)
            source = json.loads(payload)
            if (
                not isinstance(source, list)
                or not source
                or any(not isinstance(e, dict) for e in source)
            ):
                raise ValueError("invalid driver catalog")
            snapshot = hashlib.sha256(payload).hexdigest()
            entries = []
            for entry in source:
                pruned = {
                    k: entry[k]
                    for k in (
                        "Id",
                        "Tags",
                        "Category",
                        "Description",
                        "MitreID",
                        "Commands",
                        "Resources",
                    )
                    if k in entry
                }
                pruned["KnownVulnerableSamples"] = [
                    {
                        k: sample[k]
                        for k in ("Filename", "OriginalFilename", "SHA256", "SHA1", "MD5")
                        if k in sample
                    }
                    for sample in entry.get("KnownVulnerableSamples", [])
                    if isinstance(sample, dict)
                ]
                entries.append(pruned)
            atomic_write_text(cache, json.dumps({"snapshot_sha256": snapshot, "entries": entries}))
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
                str(sample.get("SHA256", "")).lower() in hashes
                for sample in entry.get("KnownVulnerableSamples", [])
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
