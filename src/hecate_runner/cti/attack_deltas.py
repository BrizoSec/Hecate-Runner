"""Monthly STIX technique/procedure deltas scoped to uncovered corpus techniques."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.cti.base import CTIItem, CTIProvider
from hecate_runner.integration_health import record_health


class AttackDeltaProvider(CTIProvider):
    name = "attack_deltas"

    def __init__(
        self,
        workspace: Path,
        *,
        client: httpx.Client | None = None,
        interval_seconds: int = 30 * 86400,
        **kwargs: Any,
    ):
        self.workspace = workspace
        self.client = client or httpx.Client(timeout=60, follow_redirects=True)
        self.owns_client = client is None
        self.interval_seconds = interval_seconds
        self.headers = {"User-Agent": "Hecate-Runner/1.0"}
        if kwargs.get("github_token"):
            self.headers["Authorization"] = f"Bearer {kwargs['github_token']}"
        self.cursor_file = workspace / ".cursors" / "attack_deltas_cursor.json"

    def close(self) -> None:
        if self.owns_client:
            self.client.close()

    def covered(self) -> set[str]:
        covered: set[str] = set()
        for path in (self.workspace / "hunts").rglob("H-*.md"):
            text = path.read_text()
            try:
                meta = yaml.safe_load(text.split("---", 2)[1])
                if meta.get("status") != "archived":
                    covered.update(meta.get("techniques") or [])
            except (IndexError, AttributeError, yaml.YAMLError):
                continue
        return covered

    def save(self, state: dict[str, Any]) -> None:
        atomic_write_text(self.cursor_file, json.dumps(state))

    def next_item(self) -> CTIItem | None:
        try:
            state = json.loads(self.cursor_file.read_text()) if self.cursor_file.exists() else {}
            if (
                not state.get("pending")
                and time.time() - state.get("checked", 0) >= self.interval_seconds
            ):
                fingerprints, objects = {}, {}
                covered = self.covered()
                head = self.client.get(
                    "https://api.github.com/repos/mitre-attack/attack-stix-data/commits/master",
                    headers=self.headers,
                )
                head.raise_for_status()
                revision = str(head.json()["sha"])
                if not re.fullmatch("[a-f0-9]{40}", revision):
                    raise ValueError("invalid ATT&CK revision")
                for domain in ("enterprise-attack", "ics-attack"):
                    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{revision}/{domain}/{domain}.json"
                    r = self.client.get(url)
                    r.raise_for_status()
                    if len(r.content) > 80_000_000:
                        raise ValueError("STIX bundle exceeds size limit")
                    bundle = r.json()
                    if bundle.get("type") != "bundle" or not isinstance(
                        bundle.get("objects"), list
                    ):
                        raise ValueError("invalid STIX bundle")
                    for obj in bundle["objects"]:
                        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                            continue
                        if obj.get("type") == "attack-pattern" or (
                            obj.get("type") == "relationship"
                            and obj.get("relationship_type") == "uses"
                            and obj.get("description")
                        ):
                            objects[obj["id"]] = {**obj, "_source_url": url, "_revision": revision}
                            fingerprints[obj["id"]] = hashlib.sha256(
                                json.dumps(
                                    {
                                        k: v
                                        for k, v in obj.items()
                                        if k
                                        not in {
                                            "modified",
                                            "created",
                                            "x_mitre_version",
                                            "x_mitre_attack_spec_version",
                                        }
                                    },
                                    sort_keys=True,
                                ).encode()
                            ).hexdigest()
                if not any(o.get("type") == "attack-pattern" for o in objects.values()):
                    raise ValueError("STIX has no techniques")
                pending = []
                if "fingerprints" in state:
                    changed = {
                        k for k, v in fingerprints.items() if state["fingerprints"].get(k) != v
                    }
                    targets = {k for k in changed if objects[k].get("type") == "attack-pattern"}
                    targets.update(
                        objects[k].get("target_ref")
                        for k in changed
                        if objects[k].get("type") == "relationship"
                    )
                    for target in sorted(t for t in targets if t in objects):
                        obj = objects[target]
                        tid = next(
                            (
                                ref.get("external_id")
                                for ref in obj.get("external_references", [])
                                if re.fullmatch(
                                    r"T\d{4}(?:\.\d{3})?", str(ref.get("external_id", ""))
                                )
                            ),
                            None,
                        )
                        if not tid or tid in covered:
                            continue
                        procedures = [
                            o
                            for k, o in objects.items()
                            if k in changed and o.get("target_ref") == target
                        ]
                        pending.append(
                            {
                                "technique": obj,
                                "technique_id": tid,
                                "procedures": procedures,
                                "reason": "changed ATT&CK technique/procedure has no non-archived hunt coverage",
                            }
                        )
                state = {"fingerprints": fingerprints, "checked": time.time(), "pending": pending}
                self.save(state)
                record_health(
                    self.workspace,
                    self.name,
                    True,
                    "enterprise and ICS STIX baseline/delta validated",
                )
            # Corpus coverage may have changed while a monthly batch was pending.
            if not state.get("pending"):
                return None
            covered = self.covered()
            while state.get("pending") and state["pending"][0]["technique_id"] in covered:
                state["pending"].pop(0)
                self.save(state)
            if not state.get("pending"):
                return None
            change = state["pending"][0]
            obj = change["technique"]
            tid = change["technique_id"]
            content = (
                f"Title: ATT&CK delta: {tid} {obj['name']}\n"
                f"MITRE ATT&CK Techniques: {tid}\nReason: {change['reason']}\n"
                "Reference taxonomy and documented procedure examples; not a newly observed incident.\n"
                + json.dumps(change, ensure_ascii=False)
            )
            return CTIItem(
                content=content,
                title=f"ATT&CK delta: {tid} {obj['name']}",
                source=self.name,
                source_url=f"{obj['_source_url']}#{obj['id']}",
                received_at=datetime.now(UTC),
                identifier=f"{tid}:{obj.get('modified', '')}:{hashlib.sha256(content.encode()).hexdigest()[:16]}",
                metadata={
                    "processing_track": "deep",
                    "evidence_profile": "taxonomy_delta",
                    "technique_id": tid,
                    "delta": change,
                    "source_revision": obj["_revision"],
                    "reference_only": True,
                },
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            record_health(
                self.workspace,
                self.name,
                False,
                "STIX fetch/schema failure; prior baseline retained",
            )
            raise

    def acknowledge(self, item: CTIItem) -> None:
        state = json.loads(self.cursor_file.read_text())
        state["pending"] = [v for v in state["pending"] if v != item.metadata["delta"]]
        self.save(state)
