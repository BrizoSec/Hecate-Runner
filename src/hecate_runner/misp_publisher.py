"""Durable, idempotent storage of pipeline artifacts in the operator's MISP instance.

Events stay organization-only and unpublished. Candidate indicators never become
IDS rules just because a hunt was drafted. No notifications or MISP publish/alert
actions are invoked. A retry verifies remote contents before confirming success.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4, uuid5

import httpx
import yaml
from hecate_agent.core.provenance import refang

from hecate_runner.config import Settings
from hecate_runner.github_publisher import snapshot_hunt_artifacts
from hecate_runner.integration_health import protect_request_logs

log = logging.getLogger(__name__)


class MispPublishError(RuntimeError):
    """A MISP export did not complete or its read-back verification failed."""


def _target(settings: Settings) -> str:
    return str(settings.misp_base_url or "").rstrip("/")


def _writer_key(settings: Settings) -> str | None:
    return settings.misp_output_api_key or settings.misp_api_key


def _database(settings: Settings) -> Path:
    return settings.hecate_workspace / ".hecate" / "misp" / "outbox.sqlite3"


@contextmanager
def _connect(settings: Settings) -> Iterator[sqlite3.Connection]:
    path = _database(settings)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    db = sqlite3.connect(path, timeout=30)
    path.chmod(0o600)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute(
        """CREATE TABLE IF NOT EXISTS exports (
        target TEXT NOT NULL, hunt_id TEXT NOT NULL, event_uuid TEXT NOT NULL,
        digest TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
        event_id TEXT, last_error TEXT NOT NULL DEFAULT '', confirmed_at TEXT,
        PRIMARY KEY (target, hunt_id))"""
    )
    try:
        with db:
            yield db
    finally:
        db.close()


def _indicator_attribute(record: dict[str, Any]) -> tuple[str, str] | None:
    """Only explicitly typed, syntactically valid values become searchable attributes."""
    kind = str(record.get("type", "")).lower()
    value = refang(str(record.get("value", ""))).strip()
    if not value or len(value) > 2048:
        return None
    if kind in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        if address.version != (4 if kind == "ipv4" else 6):
            return None
        return ("ip-src" if record.get("role") == "inbound" else "ip-dst", str(address))
    if kind in {"md5", "sha1", "sha256", "imphash"}:
        if record.get("role") == "non_file":
            return None
        length = {"md5": 32, "sha1": 40, "sha256": 64, "imphash": 32}[kind]
        return (kind, value.lower()) if re.fullmatch(rf"[a-fA-F0-9]{{{length}}}", value) else None
    if kind in {"domain", "hostname"}:
        value = value.lower().rstrip(".")
        if len(value) <= 253 and re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value
        ):
            return kind, value
    if kind == "url":
        try:
            parsed = urlsplit(value)
            if parsed.scheme in {"http", "https"} and parsed.hostname:
                return "url", value
        except ValueError:
            return None
    return None


def _payload(
    hunt_id: str,
    files: dict[str, str],
    digest: str,
    event_uuid: str,
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    namespace = UUID(event_uuid)
    hunt_text = next(text for path, text in files.items() if path.startswith("hunts/"))
    metadata = yaml.safe_load(hunt_text.split("---", 2)[1]) or {}
    attributes: list[dict[str, Any]] = []
    reports = []
    for path, text in sorted(files.items()):
        attributes.append(
            {
                "uuid": str(uuid5(namespace, "file:" + path)),
                "type": "attachment",
                "category": "External analysis",
                "value": Path(path).name,
                "data": base64.b64encode(text.encode()).decode(),
                "to_ids": False,
                "distribution": "5",
                "comment": f"Hecate artifact: {path}; snapshot {digest}",
            }
        )
        if path.startswith(("hunts/", "research/")):
            reports.append(
                {
                    "uuid": str(uuid5(namespace, "report:" + path)),
                    "name": f"Hecate: {path}",
                    "distribution": "5",
                    "content": text,
                }
            )
    seen = set()
    for record in records:
        pair = _indicator_attribute(record)
        if pair is None or pair in seen:
            continue
        seen.add(pair)
        kind, value = pair
        provenance = {
            k: record.get(k, "unknown")
            for k in ("role", "status", "confidence", "source", "evidence")
        }
        attributes.append(
            {
                "uuid": str(uuid5(namespace, f"indicator:{kind}:{value}")),
                "type": kind,
                "value": value,
                "to_ids": False,
                "distribution": "5",
                "comment": "Hecate candidate; requires review. "
                + json.dumps(provenance, ensure_ascii=False),
            }
        )
    # Preserve records that cannot be represented as MISP indicator types, too.
    if records:
        reports.append(
            {
                "uuid": str(uuid5(namespace, "indicator-provenance")),
                "name": f"Hecate {hunt_id}: indicator provenance",
                "distribution": "5",
                "content": "```json\n"
                + json.dumps(records, indent=2, ensure_ascii=False)
                + "\n```",
            }
        )
    return {
        "Event": {
            "uuid": event_uuid,
            "info": f"Hecate Hunt: {hunt_id} - {metadata.get('title', hunt_id)}"[:255],
            "date": str(metadata.get("date") or datetime.now(UTC).date())[:10],
            "distribution": "0",
            "published": False,
            "analysis": "0",
            "threat_level_id": "4",
            "Attribute": attributes,
            "EventReport": reports,
        }
    }


def enqueue_misp_hunt(
    settings: Settings,
    hunt_id: str,
    *,
    indicator_records: list[dict[str, Any]] | None = None,
) -> str:
    if not settings.misp_publishing_enabled:
        raise MispPublishError("MISP output is disabled")
    if not (settings.misp_base_url and _writer_key(settings)):
        raise MispPublishError("MISP_BASE_URL and a MISP writer API key are required")
    files, _ = snapshot_hunt_artifacts(settings, hunt_id)
    records = indicator_records or []
    digest = hashlib.sha256(
        json.dumps({"files": files, "records": records}, sort_keys=True).encode()
    ).hexdigest()
    with _connect(settings) as db:
        db.execute("BEGIN IMMEDIATE")
        old = db.execute(
            "SELECT * FROM exports WHERE target=? AND hunt_id=?", (_target(settings), hunt_id)
        ).fetchone()
        if old and old["digest"] == digest:
            return str(old["status"])
        event_uuid = str(old["event_uuid"]) if old else str(uuid4())
        payload = json.dumps(_payload(hunt_id, files, digest, event_uuid, records))
        db.execute(
            """INSERT INTO exports (target,hunt_id,event_uuid,digest,payload,status)
            VALUES (?,?,?,?,?,'pending') ON CONFLICT(target,hunt_id) DO UPDATE SET
            digest=excluded.digest,payload=excluded.payload,status='pending',attempts=0,
            next_attempt=0,last_error=''""",
            (_target(settings), hunt_id, event_uuid, digest, payload),
        )
    return "pending"


def misp_publication_status(settings: Settings) -> list[dict[str, Any]]:
    if not _database(settings).exists():
        return []
    with _connect(settings) as db:
        return [
            dict(row)
            for row in db.execute(
                """SELECT hunt_id,event_uuid,event_id,status,attempts,last_error,confirmed_at
            FROM exports WHERE target=? ORDER BY hunt_id""",
                (_target(settings),),
            )
        ]


def _request(client: httpx.Client, method: str, path: str, **kwargs: Any) -> httpx.Response:
    try:
        response = client.request(method, path, **kwargs)
    except httpx.RequestError as exc:
        raise MispPublishError(type(exc).__name__) from exc
    if response.status_code >= 400 and response.status_code != 404:
        raise MispPublishError(f"MISP HTTP {response.status_code}")
    return response


def _event(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
        event = data.get("Event", {})
        if not isinstance(event, dict) or not event.get("id") or not event.get("uuid"):
            raise ValueError
        return event
    except (ValueError, AttributeError, TypeError) as exc:
        raise MispPublishError("MISP did not return a valid event") from exc


def _publish(client: httpx.Client, row: sqlite3.Row) -> str:
    payload = json.loads(row["payload"])
    expected = payload["Event"]
    path = "/events/view/" + row["event_uuid"]
    existing = _request(client, "GET", path)
    endpoint = (
        "/events/add"
        if existing.status_code == 404
        else "/events/edit/" + str(_event(existing)["id"])
    )
    # On a retry, stable event/report/attribute UUIDs reconcile the same objects.
    _event(_request(client, "POST", endpoint, json=payload))
    saved = _event(_request(client, "GET", path, params={"includeAttachments": 1}))
    if (
        saved["uuid"] != row["event_uuid"]
        or str(saved.get("distribution")) != "0"
        or saved.get("published") not in (False, 0, "0")
    ):
        raise MispPublishError("MISP event controls failed read-back verification")
    actual_attributes = {a["uuid"]: a for a in saved.get("Attribute", [])}
    for attribute in expected["Attribute"]:
        actual = actual_attributes.get(attribute["uuid"], {})
        if any(actual.get(k) != attribute[k] for k in ("type", "value", "comment")) or actual.get(
            "to_ids"
        ) not in (False, 0, "0"):
            raise MispPublishError("MISP attributes failed read-back verification")
        if attribute["type"] == "attachment" and actual.get("data") != attribute["data"]:
            raise MispPublishError("MISP attachment content failed read-back verification")
    actual_reports = {r["uuid"]: r for r in saved.get("EventReport", [])}
    if any(
        actual_reports.get(r["uuid"], {}).get("content") != r["content"]
        for r in expected["EventReport"]
    ):
        raise MispPublishError("MISP reports failed read-back verification")
    return str(saved["id"])


def sync_misp_outbox(
    settings: Settings,
    *,
    client: httpx.Client | None = None,
    max_items: int = 5,
) -> list[dict[str, str]]:
    if not settings.misp_publishing_enabled or not _database(settings).exists():
        return []
    writer_key = _writer_key(settings)
    if not (settings.misp_base_url and writer_key):
        raise MispPublishError("MISP_BASE_URL and a MISP writer API key are required")
    protect_request_logs()
    own_client = client is None
    client = client or httpx.Client(
        base_url=_target(settings),
        timeout=settings.misp_request_timeout_sec,
        verify=settings.misp_verify_ssl,
        headers={
            "Authorization": writer_key,
            "Accept": "application/json",
            "User-Agent": "Hecate-MISP-Output/1.0",
        },
    )
    results = []
    try:
        for _ in range(max_items):
            with _connect(settings) as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute(
                    "SELECT * FROM exports WHERE target=? AND status!='confirmed' AND next_attempt<=? ORDER BY hunt_id LIMIT 1",
                    (_target(settings), time.time()),
                ).fetchone()
                if row is None:
                    break
                db.execute(
                    "UPDATE exports SET status='sending',next_attempt=? WHERE target=? AND hunt_id=?",
                    (time.time() + 300, _target(settings), row["hunt_id"]),
                )
            try:
                event_id = _publish(client, row)
                with _connect(settings) as db:
                    db.execute(
                        "UPDATE exports SET status='confirmed',event_id=?,confirmed_at=?,last_error='' WHERE target=? AND hunt_id=? AND digest=?",
                        (
                            event_id,
                            datetime.now(UTC).isoformat(),
                            _target(settings),
                            row["hunt_id"],
                            row["digest"],
                        ),
                    )
                results.append({"hunt_id": row["hunt_id"], "event_id": event_id})
            except Exception as exc:
                detail = str(exc) if isinstance(exc, MispPublishError) else type(exc).__name__
                with _connect(settings) as db:
                    db.execute(
                        "UPDATE exports SET status='pending',attempts=attempts+1,next_attempt=?,last_error=? WHERE target=? AND hunt_id=? AND digest=?",
                        (
                            time.time() + min(3600, 30 * 2 ** min(row["attempts"], 7)),
                            detail,
                            _target(settings),
                            row["hunt_id"],
                            row["digest"],
                        ),
                    )
                log.warning("MISP export for %s remains queued: %s", row["hunt_id"], detail)
    finally:
        if own_client:
            client.close()
    return results
