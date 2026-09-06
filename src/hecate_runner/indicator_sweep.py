"""Deterministic indicator-sweep drafts for narrative-free CTI.

A daily feed dump (ThreatFox, Maltrail) is a list of indicators and nothing
else. It supports exactly one hunt -- "do any of these appear in our
telemetry?" -- and no behavioral hypothesis at all: it names no delivery
mechanism, no actor, no malware family and no technique.

Putting that through the hypothesis-generator was a category error, and the
model filled the gap the only way it could. Observed in live drafts from
feeds containing nothing but domains and IPs: "phishing emails" invented as
the delivery vector (H-0009), "anomalous account logins and process
creations" (H-0012), "stolen credentials ... lateral movement" plus an
unsupported T1091 Replication Through Removable Media (H-0023).

So this module builds the draft directly from the indicator inventory the
CTI blurb already states, with no LLM in the path -- there is no slot for
the model to fill, so there is nothing for it to invent.
"""

from __future__ import annotations

import re

from hecate_runner.athf_client import HypothesisResult

# The inventory line each provider emits: MISP's `_event_to_blurb` writes
# "Attributes (245 total): domain (146), ip-dst|port (78), url (21)" and
# OTX's `_pulse_to_blurb` writes "Indicators (22 total): domain (21),
# hostname (1)". Both are machine-generated from real attribute counts, so
# parsing them is reading the provider's own inventory rather than guessing
# at free text.
_INVENTORY_RE = re.compile(r"^(?:Attributes|Indicators) \(\d+ total\):\s*(.+)$", re.MULTILINE)
_TYPE_COUNT_RE = re.compile(r"([A-Za-z0-9_|\-]+)\s*\((\d+)\)")

# Indicator type -> (telemetry to search, what a match looks like). Keys are
# lowercased; MISP and OTX spell the same concept differently ("ip-dst" vs
# "IPv4"), so both spellings map to the same entry.
_TELEMETRY_BY_TYPE: dict[str, tuple[str, str]] = {
    "domain": ("DNS query logs", "DNS resolution of a listed domain"),
    "hostname": ("DNS query logs", "DNS resolution of a listed hostname"),
    "url": ("Web proxy / HTTP logs", "HTTP request to a listed URL"),
    "ip-dst": ("Network flow / firewall logs", "Outbound connection to a listed IP"),
    "ip-src": ("Network flow / firewall logs", "Inbound connection from a listed IP"),
    "ip-dst|port": ("Network flow / firewall logs", "Outbound connection to a listed IP:port"),
    "ipv4": ("Network flow / firewall logs", "Connection to a listed IPv4 address"),
    "ipv6": ("Network flow / firewall logs", "Connection to a listed IPv6 address"),
    "md5": ("Endpoint/EDR file and process telemetry", "Execution of a file matching a listed MD5"),
    "sha1": (
        "Endpoint/EDR file and process telemetry",
        "Execution of a file matching a listed SHA1",
    ),
    "sha256": (
        "Endpoint/EDR file and process telemetry",
        "Execution of a file matching a listed SHA256",
    ),
    "filehash-md5": (
        "Endpoint/EDR file and process telemetry",
        "Execution of a file matching a listed MD5",
    ),
    "filehash-sha1": (
        "Endpoint/EDR file and process telemetry",
        "Execution of a file matching a listed SHA1",
    ),
    "filehash-sha256": (
        "Endpoint/EDR file and process telemetry",
        "Execution of a file matching a listed SHA256",
    ),
    "email": ("Mail gateway logs", "Mail from or to a listed address"),
    "email-src": ("Mail gateway logs", "Mail from a listed sender address"),
}


def parse_indicator_inventory(cti_content: str) -> dict[str, int]:
    """Return {indicator_type: count} from the CTI blurb's inventory line.

    Empty dict when there is no such line -- which is the signal that this
    CTI is *not* a recognisable feed dump, whatever else it may be. Callers
    must treat that as "don't build a sweep draft" rather than "build one
    with no indicators": an empty result means we could not confirm the
    shape of the source, not that the source is empty.
    """
    match = _INVENTORY_RE.search(cti_content)
    if not match:
        return {}

    inventory: dict[str, int] = {}
    for type_name, count in _TYPE_COUNT_RE.findall(match.group(1)):
        key = type_name.lower()
        # Same concept can appear twice under different spellings; sum them
        # rather than letting the later one silently win.
        inventory[key] = inventory.get(key, 0) + int(count)
    return inventory


def _source_label(cti_content: str, title: str | None) -> str:
    """Human-readable name for the feed/event the indicators came from."""
    if title and title.strip():
        return title.strip()
    first_line = cti_content.strip().splitlines()[0] if cti_content.strip() else ""
    # Blurbs open with "MISP Event: <info>" / "OTX Pulse: <name>".
    if ":" in first_line:
        return first_line.split(":", 1)[1].strip() or first_line.strip()
    return first_line.strip() or "the source feed"


def build_indicator_sweep(cti_content: str, title: str | None = None) -> HypothesisResult:
    """Build a hunt draft for a narrative-free indicator dump, without an LLM.

    Every field is derived from the indicator types the CTI blurb itself
    reports, so the draft cannot claim more than the source does. In
    particular `techniques` stays empty: an indicator list evidences no
    ATT&CK technique, and an empty list is now rendered as an explicit gap
    for the reviewer rather than a "TXXXX" placeholder.
    """
    inventory = parse_indicator_inventory(cti_content)
    source = _source_label(cti_content, title)

    telemetry: list[str] = []
    observables: list[str] = []
    for type_name in sorted(inventory):
        mapped = _TELEMETRY_BY_TYPE.get(type_name)
        if mapped is None:
            # An unmapped type is still worth stating -- the reviewer can see
            # what came in and route it -- but it contributes no invented
            # telemetry source.
            observables.append(
                f"Presence of a listed {type_name} indicator ({inventory[type_name]} in feed)"
            )
            continue
        source_name, observable = mapped
        if source_name not in telemetry:
            telemetry.append(source_name)
        observables.append(f"{observable} ({inventory[type_name]} in feed)")

    total = sum(inventory.values())
    counts = ", ".join(f"{type_name} ({inventory[type_name]})" for type_name in sorted(inventory))

    return HypothesisResult(
        hypothesis=(f"Indicators published in {source} appear in environment telemetry."),
        justification=(
            f"{source} published {total} indicator(s) ({counts}). This draft is an "
            "indicator sweep: it tests only whether those indicators appear in our "
            "own telemetry. The source carries no narrative describing how they were "
            "used, so it supports no hypothesis about adversary behavior, tooling or "
            "technique -- a reviewer wanting one should start from a source that "
            "describes the activity."
        ),
        # Intentionally empty: an indicator list evidences no ATT&CK technique.
        techniques=[],
        data_sources=telemetry,
        observables=observables,
        false_positives=[
            "Legitimate software or services resolving/connecting to a listed indicator",
            "Security tooling (sandboxes, scanners, threat-intel enrichment) fetching listed indicators",
            "Stale or recycled infrastructure now serving benign content",
        ],
        actor="",
        behavior=f"Presence of infrastructure listed in {source} within environment telemetry",
        location="",
        evidence=", ".join(telemetry),
        # A feed dump is genuine threat intel, so this stays True -- it is not
        # the vendor-marketing case `is_threat_report` exists to flag.
        is_threat_report=True,
        is_indicator_only=True,
    )
