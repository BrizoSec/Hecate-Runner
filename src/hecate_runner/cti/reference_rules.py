"""Literal-only detection candidates from structured references; never execute templates."""

from __future__ import annotations

import re
from typing import Any


def template_requests(requests: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Concrete request projections; ignore unresolved payloads and response matchers."""
    output = []
    for request in requests:
        candidates = []
        for path in request.get("path", []):
            # Only the authority macro has a known projection into URI telemetry.
            uri = re.sub(r"^{{(?:BaseURL|RootURL)}}", "", str(path))
            candidates.append((str(request.get("method", "GET")), uri))
        for raw in request.get("raw", []):
            first_line = str(raw).splitlines()[0] if str(raw).splitlines() else ""
            match = re.fullmatch(r"([A-Z]+) (\S+) HTTP/\d(?:\.\d)?", first_line)
            if match:
                candidates.append((match[1], match[2]))
        for method, uri in candidates:
            if (
                not uri.startswith("/")
                or re.search(r"{{|}}|\$|[\r\n]", uri)
                or not re.fullmatch("[A-Z]+", method)
            ):
                continue
            output.append({"method": method, "uri": uri})
    return output


def reference_candidates(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    if metadata.get("evidence_profile") == "behavior_catalog":
        for artifact in metadata.get("source_artifacts", []):
            command = str(artifact.get("value", ""))
            prefix = re.split(r"\{|\$|%[A-Za-z_]+%|<", command, maxsplit=1)[0].strip()
            match = re.match(r"^([\w.\\/+-]+)\s+(.+)", prefix)
            if not match or "\n" in prefix:
                continue
            program = match[1].replace("\\", "/").rsplit("/", 1)[-1]
            if program in {"cd", "export", "echo", "read", "source", "alias"} or len(match[2]) < 3:
                continue
            image = ("\\" if metadata.get("platform") == "Windows" else "/") + program
            output.append(
                {
                    "category": "process_creation",
                    "platform": metadata.get("platform", "").lower(),
                    "title": f"Catalog abuse procedure: {prefix}"[:110],
                    "level": "medium",
                    "detection": {
                        "selection": {"Image|endswith": image, "CommandLine|contains": prefix},
                        "condition": "selection",
                    },
                    "command": command,
                    "behaviour": prefix,
                    "passage": command,
                }
            )
    for request in template_requests(metadata.get("http_requests") or []):
        uri = request["uri"]
        path, _, query = uri.partition("?")
        selection = {"cs-method": request["method"], "cs-uri-stem": path}
        if query:
            selection["cs-uri-query"] = query
        output.append(
            {
                "category": "webserver",
                "title": f"Nuclei reference request: {request['method']} {uri}"[:110],
                "detection": {"selection": selection, "condition": "selection"},
                "level": "medium",
                "command": f"{request['method']} {uri}",
                "behaviour": f"{request['method']} {uri}",
                "passage": f"Documented probe request: {request['method']} {uri}",
            }
        )
    return output
