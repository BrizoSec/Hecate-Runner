"""Persist actual read-only integration checks separately from configuration."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_runner.atomic_write import atomic_write_text


def record_health(
    workspace: Path, name: str, healthy: bool, detail: str = "", *, enabled: bool = True
) -> dict[str, Any]:
    # Callers supply bounded status descriptions, never HTTP bodies or credentials.
    record = {
        "enabled": enabled,
        "healthy": bool(healthy and enabled),
        "detail": detail[:160],
        "checked_at": datetime.now(UTC).isoformat(),
    }
    atomic_write_text(workspace / ".hecate" / "integrations" / f"{name}.json", json.dumps(record))
    return record


class URLSecretFilter(logging.Filter):
    """httpx logs URLs even in DEBUG deployments; query credentials must stay private."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = re.sub(
            r"(?i)([?&](?:key|token)=)[^&\s\"']+", r"\1[redacted]", record.getMessage()
        )
        record.args = ()
        return True


def protect_request_logs() -> None:
    logger = logging.getLogger("httpx")
    if not any(isinstance(f, URLSecretFilter) for f in logger.filters):
        logger.addFilter(URLSecretFilter())
