"""Main orchestrator loop.

One run == one cycle: pick up CTI, call hecate, write a draft. Composable so
tests can drive it with fakes and so a future long-running loop could reuse
the same ``run_once`` primitive.
"""

from __future__ import annotations

import functools
import logging
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hecate_agent.core.grounding import (
    TechniqueFact,
    audit_draft,
    render_grounding_section,
    technique_lacks_evidence,
)
from hecate_agent.core.hunt_ids import hunt_id_lock, next_hunt_id

from hecate_runner.atomic_write import atomic_write_text
from hecate_runner.config import Settings
from hecate_runner.context_metrics import measure_tokens
from hecate_runner.cti import ATTACK_TECHNIQUE_LINE, CTIItem, CTIProvider, get_provider
from hecate_runner.cti_triage import triage
from hecate_runner.hecate_client import HecateClient, HecateError, HypothesisResult
from hecate_runner.hunt_writer import (
    DraftHuntRequest,
    render_draft,
    write_draft,
)
from hecate_runner.indicator_sweep import build_indicator_sweep, parse_indicator_inventory
from hecate_runner.metrics import CycleMetrics, LLMUsage, MetricsStore
from hecate_runner.notifications import notify_draft_created
from hecate_runner.parked_store import park, prune_parked
from hecate_runner.state import OrchestratorState
from hecate_runner.trail import CycleTrail, clip, counts, listing

log = logging.getLogger(__name__)

# MITRE technique IDs embedded in raw CTI text, e.g. "T1003.001" or "T1053.005".
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# `hecate-agent research new --topic` expects a short label, not a raw CTI paragraph.
_TOPIC_MAX_LEN = 100

# A technique whose ATT&CK platform list is this broad (of the ~10 platforms
# ATT&CK currently defines) doesn't meaningfully scope a hunt -- e.g. T1078
# "Valid Accounts" and T1098 "Account Manipulation" both list all 10. Left
# in the union unconditionally, one such technique in a hypothesis's
# technique list (alongside genuinely narrow ones, e.g. a Windows-only
# technique) was enough to make `platform` list every ATT&CK platform verbatim
# regardless of what the CTI actually described -- 37% of one drafting batch.
# See `_resolve_ttps`.
_NON_SCOPING_PLATFORM_THRESHOLD = 8

#: The indicator-sweep hypothesis template is "Indicators published in
#: [source] appear in [telemetry] on [target]". A model that leaves [source]
#: empty yields "published in  appear" -- which reaches the draft twice, as
#: the frontmatter title and as the Hypothesis Statement, and reads like a
#: truncation bug rather than a missing value. The CTI item's own title is
#: exactly the value that belongs in that slot, so fill it here rather than
#: hoping the model stops omitting it.
#: Platform names ATT&CK uses, keyed by how a hypothesis is likely to spell
#: them. Used to scope a draft's platform list by what the hypothesis actually
#: claims: a union across every technique the CTI asserted returned
#: ESXi/Linux/macOS/Network Devices/Windows for a hypothesis whose own text
#: said "compromised Windows systems" and whose ABLE Location said "Windows
#: domain-joined endpoints".
_PLATFORM_MENTIONS: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "mac os": "macOS",
    "esxi": "ESXi",
    "network device": "Network Devices",
    "network devices": "Network Devices",
    "container": "Containers",
    "containers": "Containers",
    "kubernetes": "Containers",
    "docker": "Containers",
    "k8s": "Containers",
    "identity provider": "Identity Provider",
    "entra id": "Identity Provider",
    "entra": "Identity Provider",
    "azure ad": "Identity Provider",
    "okta": "Identity Provider",
    "office suite": "Office Suite",
    "office 365": "Office Suite",
    "m365": "Office Suite",
    "saas": "SaaS",
    "iaas": "IaaS",
    "aws": "IaaS",
    "azure": "IaaS",
    "gcp": "IaaS",
    "cloud": "IaaS",
}

#: Artifacts that exist on one platform only, read from the *intel* (never the
#: hypothesis) when the hypothesis names no platform. DarkMe's pulse never says
#: "Windows", but it describes PIF executables, MSI installers and COM objects;
#: without these the draft was scoped to every platform its techniques run on,
#: ESXi and SaaS included. Each entry must be unambiguous: "bash" and "cron"
#: run on both Linux and macOS, so they are absent.
_PLATFORM_ARTIFACTS: dict[str, str] = {
    "powershell": "Windows",
    "msiexec": "Windows",
    "msi": "Windows",
    "rundll32": "Windows",
    "regsvr32": "Windows",
    "mshta": "Windows",
    "wmic": "Windows",
    "lsass": "Windows",
    "exe": "Windows",
    "dll": "Windows",
    "pif": "Windows",
    "lnk": "Windows",
    "hta": "Windows",
    "docx": "Windows",
    "doc": "Windows",
    "wscript": "Windows",
    "cscript": "Windows",
    "schtasks": "Windows",
    "launchdaemon": "macOS",
    "launchagent": "macOS",
    "applescript": "macOS",
    "osascript": "macOS",
    "gatekeeper": "macOS",
    "elf": "Linux",
    "systemd": "Linux",
    "auditd": "Linux",
    "nsenter": "Containers",
    "kubectl": "Containers",
    "containerd": "Containers",
    "cloudtrail": "IaaS",
    "assumerole": "IaaS",
    "oauth": "Identity Provider",
}

#: Telemetry a technique implies, by ID prefix so sub-techniques inherit. Uses
#: the same four category names the research document and hypothesis agent
#: already speak, so a derived source and a model-proposed one are comparable.
_TECHNIQUE_DATA_SOURCES: dict[str, tuple[str, ...]] = {
    "T1059": ("process_execution",),
    "T1106": ("process_execution",),
    "T1204": ("process_execution",),
    "T1140": ("process_execution",),
    "T1620": ("process_execution",),
    "T1027": ("process_execution", "file_operations"),
    "T1005": ("file_operations", "process_execution"),
    "T1083": ("file_operations", "process_execution"),
    "T1070": ("file_operations",),
    "T1574": ("file_operations",),
    "T1105": ("network_connections", "file_operations"),
    "T1041": ("network_connections",),
    "T1071": ("network_connections",),
    "T1090": ("network_connections",),
    "T1547": ("registry_events",),
    "T1543": ("registry_events", "process_execution"),
    "T1112": ("registry_events",),
}

#: Indicator type -> telemetry that could match it. Covers both providers'
#: spellings (MISP's "ip-dst", OTX's "IPv4"); lookups lowercase the type.
_INDICATOR_DATA_SOURCES: dict[str, tuple[str, ...]] = {
    "ip-dst": ("network_connections",),
    "ip-src": ("network_connections",),
    "ipv4": ("network_connections",),
    "ipv6": ("network_connections",),
    "domain": ("network_connections",),
    "hostname": ("network_connections",),
    "url": ("network_connections",),
    "uri": ("network_connections",),
    "filename": ("file_operations", "process_execution"),
    "filepath": ("file_operations",),
    "md5": ("file_operations",),
    "sha1": ("file_operations",),
    "sha256": ("file_operations",),
    "filehash-md5": ("file_operations",),
    "filehash-sha1": ("file_operations",),
    "filehash-sha256": ("file_operations",),
    "regkey": ("registry_events",),
    "mutex": ("process_execution",),
}


def merge_techniques(cti_techniques: list[str], hypothesis_techniques: list[str]) -> list[str]:
    """Combine what the CTI asserted with what the hypothesis reasoned about.

    The hypothesis agent returns the two or three techniques it wrote prose
    around, and generalises sub-techniques while doing it -- a source event
    naming T1059.003 (Windows Command Shell) reached the draft as bare T1059.
    That is a real loss: T1059.003 is Windows-only, T1059 spans five
    platforms, so the imprecision propagates straight into the platform list.

    The CTI's list leads because it is the asserted evidence; the
    hypothesis's own additions follow. A bare parent is dropped when a
    sub-technique of it is present, so T1059 + T1059.003 collapses to the
    specific one rather than carrying both.
    """
    merged: list[str] = []
    for technique in [*cti_techniques, *hypothesis_techniques]:
        normalised = str(technique).upper().strip()
        if normalised and normalised not in merged:
            merged.append(normalised)

    parents_with_children = {t.split(".", 1)[0] for t in merged if "." in t}
    return [t for t in merged if "." in t or t not in parents_with_children]


_TRADECRAFT_SECTION_RE = re.compile(
    r"^## 2\. Adversary Tradecraft.*?$(.*?)(?=^## \d+\.|\Z)", re.MULTILINE | re.DOTALL
)


def research_tradecraft_text(research_doc: str) -> str:
    """The research document's Adversary Tradecraft section.

    What the retrieved sources said adversaries did. The rest of the document
    is model speculation -- gaps, focus areas, telemetry -- whose wording must
    not be able to put a technique on a hunt.
    """
    match = _TRADECRAFT_SECTION_RE.search(research_doc or "")
    return match.group(1) if match else ""


#: A markdown link or a bare URL. Research lists the pages its web search
#: returned, and their titles are not the intel: R-0012's list carried a
#: Kubernetes article and a Linux rule link, which scoped a Windows DLL
#: hijacking hunt to Linux and Containers too.
_LINK_RE = re.compile(r"\[[^\]]*\]\([^)]*\)|https?://\S+")


def platforms_evidenced_in(*texts: str) -> list[str]:
    """Platforms the intel names outright or implies by a platform-only artifact.

    Links and URLs are ignored: they cite where something was read, not where
    the activity happened.
    """
    texts = tuple(_LINK_RE.sub(" ", t) for t in texts if t)
    named = platforms_named_in(*texts)
    haystack = " ".join(texts).lower()
    for artifact, platform in _PLATFORM_ARTIFACTS.items():
        if platform not in named and re.search(r"\b" + re.escape(artifact) + r"\b", haystack):
            named.append(platform)
    return named


def platforms_named_in(*texts: str) -> list[str]:
    """Platforms a hypothesis explicitly claims, in ATT&CK's spelling."""
    haystack = " ".join(t for t in texts if t).lower()
    named: list[str] = []
    for mention, platform in _PLATFORM_MENTIONS.items():
        pattern = r"\b" + re.escape(mention) + r"\b"
        if re.search(pattern, haystack) and platform not in named:
            named.append(platform)
    return named


def derive_data_sources(techniques: list[str], indicator_types: list[str]) -> list[str]:
    """Telemetry this hunt needs, from its techniques and indicator types.

    Deterministic, and independent of both the model's vocabulary and the
    environment profile. The hypothesis agent's own list is kept and merged
    with this -- it was reaching the draft as `["process_execution"]` alone
    for a hunt whose CTI carried two C2 hostnames, four IPs and nine URLs.
    """
    found: list[str] = []
    for technique in techniques or []:
        normalised = str(technique).upper().strip()
        for prefix, sources in _TECHNIQUE_DATA_SOURCES.items():
            if normalised.startswith(prefix):
                found.extend(s for s in sources if s not in found)
    for indicator_type in indicator_types or []:
        for source in _INDICATOR_DATA_SOURCES.get(str(indicator_type).lower().strip(), ()):
            if source not in found:
                found.append(source)
    return found


#: Telemetry that only exists on a given platform. The hypothesis agent
#: proposes its own data_sources list and nothing checked it against the
#: platform the techniques actually resolved to, so a macOS hunt shipped asking
#: for `registry_events` -- telemetry macOS does not have. A reviewer scoping
#: that hunt has to notice and discard it, and an automated consumer cannot.
_PLATFORM_ONLY_DATA_SOURCES: dict[str, frozenset[str]] = {
    "registry_events": frozenset({"windows"}),
}


#: Telemetry category names the model returns as if they were observations.
#: A draft came back with "What Suspicious Looks Like" reading "Process
#: execution / Network connections / File operations" -- the data source list
#: retitled, which tells a reviewer nothing about what to look for and reads
#: as if the section had been filled in.
_DATA_SOURCE_RESTATEMENTS = frozenset(
    {
        "process execution",
        "process executions",
        "process creation",
        "file operations",
        "file operation",
        "file events",
        "network connections",
        "network connection",
        "network traffic",
        "registry events",
        "registry event",
        "dns queries",
        "dns query",
        "authentication events",
    }
)


#: Template values the model writes in place of an observation. H-0018 listed
#: `C:\path\to\malware.ps1`, `C:\path\to\rat.exe` and
#: `http://maliciousdomain.com/malware.bin` as what suspicious looks like; they
#: read as indicators, and the Sigma step, which is handed the observables,
#: wrote the first into a rule.
_PLACEHOLDER_OBSERVABLE_RE = re.compile(
    r"[\\/]path[\\/]to[\\/]"
    r"|\b(?:malicious-?domain|your-?domain|attacker-?domain)\b"
    r"|\bexample\.(?:com|org|net|test)\b"
    r"|(?:^|[\\/\s])(?:malware|malicious|rat|evil|badfile|payload)\.(?:exe|dll|ps1|bin|sh|bat|vbs|js|msi)\b"
    r"|<[a-z][a-z _-]*>",
    re.IGNORECASE,
)


_NO_OBSERVABLES = "[none proposed - human to populate]"


#: Values in a rule that are indicators, not behaviour: IPv4 addresses and MD5/SHA-1/SHA-256 hashes.
_RULE_IOC_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{64}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{32}\b"
)


def substantive_observables(observables: list[str]) -> list[str]:
    """Drop "observables" that restate the telemetry category or are templates.

    Kept deliberately narrow: an entry is dropped only when the whole string is
    a bare category name, or it contains a template value. "Process execution
    of an unsigned binary from /tmp" describes something a hunter can look for
    and stays.
    """
    kept: list[str] = []
    for observable in observables:
        text = str(observable).strip()
        normalised = text.lower().rstrip(".").replace("_", " ")
        if normalised in _DATA_SOURCE_RESTATEMENTS:
            continue
        if _PLACEHOLDER_OBSERVABLE_RE.search(text):
            continue
        if text:
            kept.append(text)
    return kept


def platform_consistent_data_sources(data_sources: list[str], platforms: list[str]) -> list[str]:
    """Drop telemetry that cannot exist on any of this hunt's platforms.

    Only drops when the platform list is non-empty and unambiguous about it.
    An empty platform list means scope is unknown, not that everything is
    excluded, so nothing is removed there -- the draft is a starting point for
    a human, and silently narrowing telemetry on no evidence is worse than
    leaving a source a reviewer can strike out.
    """
    if not platforms:
        return data_sources
    known = {str(p).strip().lower() for p in platforms if str(p).strip()}
    if not known:
        return data_sources

    kept: list[str] = []
    for source in data_sources:
        required = _PLATFORM_ONLY_DATA_SOURCES.get(str(source).strip().lower())
        if required is not None and not (known & required):
            continue
        kept.append(source)
    return kept


_EMPTY_SOURCE_SLOT = re.compile(r"(published in)\s{2,}(appear)", re.IGNORECASE)


def _fill_empty_source_slot(hypothesis: str, source_title: str | None) -> str:
    """Repair an indicator-sweep hypothesis whose [source] slot came back empty."""
    if not _EMPTY_SOURCE_SLOT.search(hypothesis):
        return hypothesis
    source = (source_title or "").strip() or "the source feed"
    return _EMPTY_SOURCE_SLOT.sub(lambda m: f"{m.group(1)} {source} {m.group(2)}", hypothesis)


# ATT&CK's own STIX data uses the literal platform value "PRE" for
# Reconnaissance/Resource-Development techniques (e.g. T1598 "Phishing for
# Information") that happen before the adversary has a foothold on any
# actual system -- there's no OS/environment to name yet. Surfaced verbatim,
# a hunt file's `platform: ["PRE"]` reads as a parsing bug or an unknown
# abbreviation, not what it actually means, to a human who has to scope a
# query against it. Translated at the same point _resolve_ttps already
# builds the platform list, not hardcoded as a special case in the template.
_PLATFORM_LABELS = {"PRE": "Pre-Compromise (reconnaissance/targeting -- not endpoint/OS-specific)"}


def derive_research_topic(cti_content: str, title: str | None = None) -> tuple[str, str | None]:
    """Best-effort (topic, technique) pair from a raw CTI blob.

    No NLP here on purpose — this only has to be good enough to seed the
    research agent's web searches; the research + hypothesis steps do the
    actual analysis.

    ``title`` should be the provider's clean, single-field title (e.g.
    RSS entry title, OTX pulse name, MISP event info) when the caller has
    one. Preferred over flattening/truncating ``cti_content`` -- that blob
    is "RSS: <title>\\nSource: <feed>\\nTags: ...\\nSummary: ...\\nLink:
    ...", and truncating *that whole string* at a fixed char count landed
    mid-"Source:"/"Summary:" label whenever the title alone was long,
    producing both a garbled `topic` field and a research doc contaminated
    with docs about "Source" website features whose name got the title
    pulled from the title alone. Falls back to the old flatten+truncate
    behavior only when no clean title is available.

    Known accepted limitation: for a title from a recurring series (e.g. a
    vendor's weekly "This Week in Cybersecurity"-style digest, republished
    under a near-identical title every week), the bare title alone doesn't
    disambiguate *which* edition the CTI item actually is -- the resulting
    ``topic`` can cause the research skills' web search (see
    search_system_internals/search_adversary_tradecraft in hecate's
    web_search.py) to ground against a *different* edition of the same
    series than the one this CTI item is actually about, since none of
    ``cti_content``'s more specific/disambiguating text (a summary
    mentioning the edition's actual stories) reaches the search query --
    only this function's ``topic`` return value does. Observed case: CTI
    title "The Good, the Bad and the Ugly in Cybersecurity - Week 32
    (2026)" (real content: a Snowflake breach plea, "Mythos 5", and
    ChainDrop's npm worm) produced a research doc grounded on a different
    week's edition entirely (CISO Assistant, "khunt", "The Com" takedown).
    Left unfixed for now: the actual hunt hypothesis stayed accurate in
    every observed case regardless, because hypothesis-generator weighs
    the raw CTI text over the research doc's synthesis when they diverge
    -- only the research doc itself (not the hunt) ends up describing the
    wrong content. Revisit if a bad research grounding ever does end up
    steering a hunt wrong, not just looking wrong on its own.
    """
    technique_match = _TECHNIQUE_RE.search(cti_content)
    technique = technique_match.group(0) if technique_match else None

    topic = (title or " ".join(cti_content.split())).strip()
    if len(topic) > _TOPIC_MAX_LEN:
        truncated = topic[:_TOPIC_MAX_LEN]
        # Prefer cutting on a word boundary so we don't hand the agent a
        # half-word topic.
        if " " in truncated:
            truncated = truncated.rsplit(" ", 1)[0]
        topic = truncated
    return topic or "Untitled CTI", technique


_ATTRIBUTION_RE = re.compile(r"^\s*Adversary/Attribution:\s*(.+?)\s*$", re.MULTILINE)
_NO_ATTRIBUTION = frozenset({"unknown", "none", "n/a", "unattributed", "-"})


def attributed_actor(cti_content: str) -> str:
    """The actor the intel's own attribution line names, or "".

    OTX pulses carry an ``Adversary/Attribution:`` line, and the hypothesis
    model left the ABLE Actor cell empty even when it named TraderTraitor
    (H-0007) or Water Hydra (H-0012). The publisher's attribution is the
    source's claim, not an inference, so it fills the cell only when the
    model offered nothing.
    """
    match = _ATTRIBUTION_RE.search(cti_content)
    if not match:
        return ""
    value = match.group(1).strip()
    return "" if value.lower() in _NO_ATTRIBUTION else value


_NARRATIVE_HEADER_RE = re.compile(
    r"(?im)^#{1,4}\s+.*(summary|analysis|tradecraft|context|background|lifecycle|overview|threat|technical|details|behavior|activity|intrusion|campaign|investigation|findings|execution|kill\s*chain|detection)"
)

_IOC_LINE_RE = re.compile(
    r"^[-*]?\s*([0-9a-f]{32,64}|\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|https?://\S+)\s*$",
    re.IGNORECASE,
)


def _has_substantive_prose(text: str, min_words: int = 40) -> bool:
    """True if text contains multi-word prose sentences beyond metadata fields and bare IOCs."""
    prose_words = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("```", "http://", "https://")):
            continue
        if re.match(r"^[A-Za-z0-9 _/-]{1,30}:\s", line) and not (
            line.startswith("Description:") or line.startswith("Summary:")
        ):
            continue
        if re.match(r"^(attributes|indicators)\s*\(\d+", line, re.IGNORECASE):
            continue
        if _IOC_LINE_RE.match(line):
            continue
        words = [
            w for w in line.split() if len(w) > 1 and not w.startswith(("http://", "https://"))
        ]
        if len(words) >= 3:
            prose_words += len(words)
            if prose_words >= min_words:
                return True
    return False


def has_narrative(cti_content: str) -> bool:
    """Whether ``cti_content`` carries substance beyond a bare indicator dump.

    All three CTI providers build their blurb around a "does this item have
    a human-written description" branch: RSS's ``_entry_to_blurb`` appends a
    ``Summary:`` line only when the entry has one, OTX's ``_pulse_to_blurb``
    appends a ``Description:`` line only when the pulse has one, and MISP's
    ``_event_to_blurb`` has no narrative field to append at all -- a MISP
    event carries a title (``info``) and structured metadata, not prose.

    An explicit ``MITRE ATT&CK Techniques:`` line counts too, and all three
    providers emit it under that same label. It is not prose, but the
    question this gates is not "is there prose" -- it is "is there anything
    here besides an IOC dump and a title." A stated technique list is an
    analyst asserting observed behavior, which is the strongest form of that
    evidence available short of prose, and it is precisely what a bulk
    indicator dump cannot produce: ThreatFox-style events carry no galaxy
    cluster, so they reach no such line.

    Without this, every MISP event failed the check no matter how well
    curated -- classified as an indicator sweep, routed past research, and
    rendered with ``techniques: []`` even though the event had just handed
    us fifteen technique IDs. That silently cancelled out the galaxy filter
    and org allowlist, whose whole purpose is selecting ATT&CK-mapped events.

    Gates two things, both failing the same way for the same reason -- a
    bare IOC-count blurb gives each step nothing real to work from, and both
    fill the gap from background knowledge rather than leaving it empty:

    - Web search during research. Tavily has nothing of substance to match,
      so it grounds on whatever else shares the topic's generic/templated
      title -- observed fabricating malware family names ("PureRAT and
      Overlord RAT") that propagated into the hunt file, unlike the
      recurring-digest-title case in `derive_research_topic` where the hunt
      stayed accurate because the CTI still had real text to fall back on.
    - Hypothesis generation. The agent's default template obliges the model
      to name a behavior, so against a list of domains it invented one --
      "phishing emails" as the delivery vector, "stolen credentials ...
      lateral movement" as follow-on activity, plus an unsupported ATT&CK
      technique. See `HecateClient.hypothesis_generator`'s indicators_only.
    """
    return (
        "Description:" in cti_content
        or "Summary:" in cti_content
        or ATTACK_TECHNIQUE_LINE in cti_content
        or bool(_NARRATIVE_HEADER_RE.search(cti_content))
        or _has_substantive_prose(cti_content)
    )


#: How many non-actionable items one cycle may walk past before giving up.
#: A feed of nothing but vendor blog posts should cost a single cycle, not an
#: unbounded walk through the archive.
_MAX_SKIPS_PER_CYCLE = 5


#: Field prefixes the providers emit. Everything a blurb says about itself
#: rather than about the threat.
_BLURB_FIELD_PREFIXES = (
    "RSS:",
    "OTX Pulse:",
    "MISP Event:",
    "Source:",
    "Link:",
    "Tags:",
    "Org:",
    "TLP:",
    "Threat Level:",
    "Adversary/Attribution:",
    "References:",
    "Indicators (",
    "Key indicators:",
    ATTACK_TECHNIQUE_LINE,
)


def _carries_free_text(cti_content: str) -> bool:
    """Whether anything here is prose rather than a provider metadata field.

    This is what separates "the blurb had no narrative field" from "there is
    no narrative". The file queue takes free-form text a human wrote --
    "APT actor X observed dumping LSASS via comsvcs.dll" -- which carries no
    `Summary:` marker and would otherwise read as empty.
    """
    for line in cti_content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Indented lines continue the field above them (values under
        # "Key indicators:").
        if line[:1].isspace():
            continue
        if stripped.startswith(_BLURB_FIELD_PREFIXES):
            continue
        return True
    return False


def is_actionable(cti_content: str) -> bool:
    """Whether there is anything here to build a hunt from.

    Three ways to qualify, and an item needs only one: a narrative field a
    hypothesis can be grounded in, a parseable indicator inventory a sweep can
    be built from, or free-form prose that is not provider metadata.

    The third clause is load-bearing. ``has_narrative`` recognises the
    *markers* provider blurbs use, so its absence is not evidence that no
    narrative exists -- and treating it as such discarded the file queue's
    hand-written CTI outright when this gate was first written.

    What is left over is the case this exists for: a blurb that is nothing but
    its own metadata. H-0630 was four lines -- title, source, tags, link --
    off a vendor marketing post, and became "Indicators published in Teaching
    AI to Reason Through Detection Triage appear in telemetry", a sweep for
    indicators that do not exist.

    This is a floor, not a quality bar. It does not ask whether the prose is
    *about* a specific threat; a conference write-up passes. That is the
    harder half of C4 and is deliberately still open.
    """
    return (
        has_narrative(cti_content)
        or bool(parse_indicator_inventory(cti_content))
        or _carries_free_text(cti_content)
    )


@dataclass
class RunResult:
    """Structured outcome of one orchestrator cycle."""

    outcome: str
    detail: str = ""
    hunt_id: str | None = None
    draft_path: Path | None = None
    research_id: str | None = None
    parked_count: int = 0

    @property
    def ok(self) -> bool:
        return self.outcome in {
            "draft_created",
            "no_cti",
            "no_actionable_cti",
            "quota_reached",
            "research_quota_reached",
            "parked_after_research",
            "parked_after_hypothesis",
            "parked_no_techniques",
        }


class Orchestrator:
    """Owns the wiring; one instance per run is fine."""

    def __init__(
        self,
        settings: Settings,
        hecate: HecateClient,
        cti_provider: CTIProvider,
        notify: Callable[[RunResult], None] | None = None,
    ):
        self.settings = settings
        self.hecate = hecate
        self.cti = cti_provider
        # Replaced at the start of every cycle; this one only serves callers
        # that use a stage method directly (tests, `_resolve_ttps`).
        self.trail = CycleTrail()
        self.metrics = CycleMetrics(self.trail.cycle_id)
        # Techniques `_resolve_ttps` dropped for contradicting the hunt's
        # platform, so the later drop step does not call them unknown IDs.
        self._platform_dropped: set[str] = set()
        # This cycle's techniques whose names the intel's wording uses, and
        # the model picks dropped for having no source at all ("ID Name").
        # Both are read back when the grounding section is rendered.
        self._wording_matched: list[str] = []
        #: Supporting passage per technique (hecate_agent.core.technique_evidence
        #: TechniqueEvidence dicts), including techniques dropped as capability-only.
        self._technique_evidence: list[dict[str, str]] = []
        self._unevidenced_dropped: list[str] = []
        #: ClaimFinding dicts from the claim audit (hecate_agent.core.claim_audit).
        self._claim_audit: list[dict[str, str]] = []
        # hecate_agent.core.source_evidence.SourceEvidence and the feed's
        # indicators typed against it (IndicatorRecord); reset every cycle.
        self._source_evidence: Any = None
        self._indicator_records: list[Any] = []
        #: The source's detection guidance (hecate_agent.core.detection_guidance
        #: GuidanceItem dicts): cited, routed, and fed to Sigma drafting.
        self._detection_guidance: list[dict[str, Any]] = []
        #: Platforms the specimen's evidence shows (platform_evidence), and the markers.
        self._specimen: list[str] = []
        self._platform_evidence: dict[str, Any] = {}
        #: The cycle's research grounding: "", "independent" or "source-only".
        self._research_grounding = ""
        self._research_grounding_label = ""
        # Defaults to a no-op so tests and callers that don't care about
        # notifications don't have to pass one.
        self.notify = notify or (lambda result: None)

    # --- Public API --------------------------------------------------------

    def run_once(self, *, dry_run: bool = False) -> RunResult:
        """Execute one cycle. Never raises; always returns a RunResult."""
        log.info("=== Orchestrator cycle starting (dry_run=%s) ===", dry_run)
        state = OrchestratorState.load(self.settings.state_file)
        self.trail = CycleTrail()
        self.metrics = CycleMetrics(self.trail.cycle_id)
        self._reset_llm_call_log()
        result = RunResult(outcome="error", detail="cycle did not complete")
        self.trail.step(
            "start",
            "cycle %s%s; drafts today %d/%d, research runs today %d/%d",
            self.trail.cycle_id,
            " (dry run)" if dry_run else "",
            state.drafts_today,
            self.settings.max_drafts_per_day,
            state.research_runs_today,
            self.settings.max_research_runs_per_day,
        )

        if self.settings.parked_max_age_days > 0:
            prune_parked(self.settings.cti_queue_dir_resolved, self.settings.parked_max_age_days)
        try:
            result = self._run_body(state, dry_run=dry_run)
            state.mark_run(success=result.ok)
            self.trail.step(
                "done",
                "%s%s%s in %.0fs",
                result.outcome,
                f" -> {result.hunt_id}" if result.hunt_id else "",
                f" ({clip(result.detail, 90)})" if result.detail else "",
                self.trail.elapsed,
            )
            return result
        except Exception as exc:  # top-level guard
            log.exception("Cycle failed unexpectedly: %s", exc)
            state.mark_run(success=False)
            self.trail.step("done", "error after %.0fs: %s", self.trail.elapsed, clip(str(exc)))
            result = RunResult(outcome="error", detail=str(exc))
            return result
        finally:
            try:
                state.save(self.settings.state_file)
            finally:
                try:
                    MetricsStore(self.settings.metrics_file).append(
                        self.metrics.to_record(
                            outcome=result.outcome,
                            hunt_id=result.hunt_id,
                            research_id=result.research_id,
                        )
                    )
                except Exception as exc:  # telemetry must not change a cycle result
                    log.warning("Could not persist stage metrics (%s)", exc)
            log.info("=== Orchestrator cycle complete ===")

    # --- Internal ----------------------------------------------------------

    def _evidence_texts(self, item: CTIItem, research_id: str | None) -> list[tuple[str, str]]:
        """(source label, text) that may evidence a technique, most authoritative first.

        Research counts only when it searched independently; source-only
        research restates the item and adds nothing a mapping could rest on.
        """
        texts = [("cti", item.content)]
        if self._source_evidence is not None and self._source_evidence.text:
            texts.append(("primary source", self._source_evidence.text))
        research = self._evidence_research_text(research_id)
        if research:
            texts.append(("research", _LINK_RE.sub(" ", research_tradecraft_text(research))))
        return texts

    def _gate_on_observed_use(
        self,
        techniques: list[str],
        asserted: list[str],
        behaviour: list[Any],
        texts: list[tuple[str, str]],
    ) -> list[str]:
        """Keep techniques the sources show in use; record the passage for each.

        - A technique whose every mention describes what a tool *can* do
          (H-0618's T1113 Screen Capture, from a VShell feature list) is
          dropped as capability-only.
        - A sub-technique the text does not support, whose parent it does, is
          generalised to the parent (T1036.001 Invalid Code Signature on a
          report that only says "disguised as a resume" becomes T1036).
        - Techniques the CTI names by ID are kept as asserted.
        """
        from hecate_agent.core.technique_evidence import technique_support

        by_id = {e.technique_id: e for e in behaviour}
        combined = "\n".join(text for _, text in texts)
        shielded = {t.upper() for t in asserted}
        kept: list[str] = []
        evidence: list[dict[str, str]] = []
        dropped: list[str] = []
        for technique_id in techniques:
            upper = technique_id.upper()
            found = by_id.get(upper)
            if found is None and upper not in shielded:
                meta = self.hecate.lookup_technique(
                    upper, timeout_sec=self.settings.llm_timeout_sec
                )
                found = technique_support(
                    upper, [meta.name] if meta.found and meta.name else [], combined
                )
                parent = upper.split(".")[0]
                if (
                    found is None
                    and "." in upper
                    and parent in by_id
                    and by_id[parent].status == "observed"
                ):
                    self.trail.step(
                        "techniques", "%s unsupported; generalised to %s", upper, parent
                    )
                    upper, found = parent, by_id[parent]
            if found is not None and found.status == "capability" and upper not in shielded:
                dropped.append(upper)
                evidence.append({**found.to_dict(), "technique_id": upper, "status": "capability"})
                continue
            if upper in kept:
                continue
            kept.append(upper)
            if found is not None:
                evidence.append({**found.to_dict(), "technique_id": upper})
            elif upper in shielded:
                evidence.append(
                    {
                        "technique_id": upper,
                        "status": "asserted",
                        "passage": "",
                        "source": "cti",
                        "behaviour": "named by ID",
                    }
                )
        if dropped:
            self.trail.step(
                "techniques", "dropped as capability only, not observed use: %s", listing(dropped)
            )
        self._technique_evidence = evidence
        return kept

    def _audit_claims(
        self,
        hypothesis: HypothesisResult,
        source_text: str = "",
        platforms: list[str] | None = None,
    ) -> None:
        """Remove observables that cannot be observed; soften capability stated as fact.

        Runs on the final technique list: persistence, exfiltration, lateral
        movement or credential theft may be stated as fact only when a
        technique of that kind survived the evidence gate. H-0618 said VShell
        "enables persistent, stealthy access" with no persistence technique
        observed, and called its on-disk Go loader "fileless".
        """
        from hecate_agent.core.claim_audit import (
            audit_observables,
            audit_prose,
            prose_value_reasons,
        )

        findings = []
        # The empty-section sentinel `substantive_observables` left is not a claim.
        observables = [o for o in hypothesis.observables if o != _NO_OBSERVABLES]
        # What the model named that extraction never returned: a file on the
        # actor's own machine, or one no covered platform can show.
        unobservable = {
            **prose_value_reasons(
                [
                    *observables,
                    hypothesis.hypothesis,
                    hypothesis.justification,
                    hypothesis.behavior,
                    hypothesis.location,
                    hypothesis.evidence,
                ],
                source_text,
                platforms or [],
            ),
            **self._unobservable_values(),
        }
        hypothesis.observables, removed = audit_observables(
            observables, "observables", unobservable
        )
        findings += removed
        hypothesis.false_positives, removed = audit_observables(
            hypothesis.false_positives, "normal baseline"
        )
        findings += removed
        if not hypothesis.observables:
            hypothesis.observables = [_NO_OBSERVABLES]
        on_disk = any(
            r.role == "executable" and r.status != "historical" for r in self._indicator_records
        )
        prose, rewritten = audit_prose(
            {
                "hypothesis": hypothesis.hypothesis,
                "justification": hypothesis.justification,
                "behavior": hypothesis.behavior,
                "location": hypothesis.location,
                "evidence": hypothesis.evidence,
            },
            {t.upper() for t in hypothesis.techniques},
            on_disk,
            source_text=source_text,
            unobservable=unobservable,
        )
        hypothesis.hypothesis = prose["hypothesis"]
        hypothesis.justification = prose["justification"]
        hypothesis.behavior = prose["behavior"]
        hypothesis.location = prose["location"]
        hypothesis.evidence = prose["evidence"]
        findings += rewritten
        findings += self._unsupported_platform_claims(hypothesis)
        self._claim_audit = [f.to_dict() for f in findings]
        if findings:
            counts = Counter(f.action for f in findings)
            self.trail.step(
                "claims",
                "audit: %s",
                ", ".join(f"{n} {action}" for action, n in sorted(counts.items())),
            )

    def _unobservable_values(self) -> dict[str, str]:
        """Values the pipeline already knows no log can show, with the reason.

        The A3 replay's observables listed a hash that exists only in memory,
        another that is network content, and ``personal_resume.exe`` from the
        report's closing joke.
        """
        reasons = {
            "memory_only": "exists only in memory; no log records it as a file",
            "network_content": "is network content, not a file on disk; no file or process event carries it",
            "historical": "is historical infrastructure, not this intrusion",
            "non_file": "is a token, key or certificate fingerprint, not the hash of a file",
            "target": "is an address the actor targeted, not infrastructure a host connects to",
        }
        out: dict[str, str] = {}
        for record in self._indicator_records:
            why = reasons.get(record.role) or reasons.get(record.status)
            if why:
                out[record.value] = why
        evidence = self._source_evidence
        for artifact in getattr(evidence, "artifacts", []) or []:
            if artifact.status != "active":
                out.setdefault(
                    artifact.value,
                    f"the source does not tie it to this intrusion ({artifact.role or 'no role'})",
                )
        return out

    def _unsupported_platform_claims(self, hypothesis: HypothesisResult) -> list[Any]:
        """Prose naming a platform the specimen's evidence does not show; flagged, not rewritten."""
        from hecate_agent.core.claim_audit import ClaimFinding

        if not self._specimen:
            return []
        flagged = []
        for name, text in (
            ("location", hypothesis.location),
            ("hypothesis", hypothesis.hypothesis),
        ):
            extra = [p for p in platforms_named_in(text) if p not in self._specimen]
            if extra:
                flagged.append(
                    ClaimFinding(
                        name,
                        text,
                        "flagged",
                        f"names {listing(extra)}, but the specimen's evidence shows only "
                        f"{listing(self._specimen)}; the hunt is scoped to the evidence",
                    )
                )
        return flagged

    def _primary_evidence_text(self, item: CTIItem) -> str:
        """The feed item plus the primary report's text and any OSINT enrichment."""
        base_text = (
            f"{item.content}\n{self._source_evidence.text}"
            if (self._source_evidence is not None and self._source_evidence.text)
            else item.content
        )
        return (
            f"{base_text}\n{self._enriched_context}"
            if hasattr(self, "_enriched_context") and self._enriched_context
            else base_text
        )

    def _evidence_research_text(self, research_id: str | None) -> str:
        """Research text that may count as evidence: none when research was source-only.

        Source-only research rephrases the item it was given, so a claim found
        only there was supplied by the model, not corroborated by a source.
        """
        if self._research_grounding == "source-only":
            return ""
        return self._research_text(research_id)

    def _reset_llm_call_log(self) -> None:
        """Start the live call log empty, so the monitor counts this cycle's calls only."""
        try:
            self.settings.log_dir.mkdir(parents=True, exist_ok=True)
            self.settings.llm_calls_file.write_text("", encoding="utf-8")
        except OSError as exc:  # the log is for watching; a cycle runs without it
            log.debug("Could not reset %s: %s", self.settings.llm_calls_file, exc)

    def _gather_source_evidence(self, item: CTIItem) -> None:
        """Fetch the item's report, extract verified evidence, and type its indicators.

        Never fails the cycle: without a report link, with the step disabled,
        or on a fetch or model failure the draft proceeds from the feed item
        and its indicators keep unknown roles.
        """
        indicators = dict(item.metadata.get("indicators") or {})
        if not self.settings.source_evidence_enabled:
            return
        from hecate_agent.core.source_evidence import report_urls

        urls = report_urls(item.content, item.source_url)
        if not urls:
            self.trail.step("source", "no report link in the item; drafting from the feed text")
            return
        self.trail.step("source", "starting: reading %s", urls[0])
        started = self.trail.elapsed
        try:
            with self.metrics.measure("source_evidence") as measured:
                import concurrent.futures

                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = executor.submit(self.hecate.source_evidence, urls[0])
                try:
                    evidence = future.result(timeout=300)
                except concurrent.futures.TimeoutError as exc:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise TimeoutError(f"Timed out after 300 seconds reading {urls[0]}") from exc

                self._source_evidence = evidence
                try:
                    if evidence.text:
                        self._indicator_records = self.hecate.indicator_records(
                            indicators, evidence
                        )
                finally:
                    # Typing the indicators calls the model too; count both passes.
                    metadata: Any = getattr(evidence, "usage_metadata", dict)()
                    if isinstance(metadata, dict) and metadata:
                        measured.set_usage(LLMUsage.from_metadata(metadata))
        except Exception as exc:  # evidence is an aid; never fatal
            log.warning("Source evidence failed for %s: %s", urls[0], exc)
            self.trail.step(
                "source", "failed for %s: %s; drafting from the feed text", urls[0], exc
            )
            return
        if evidence.error and not evidence.artifacts:
            self.trail.step(
                "source", "%s: %s; drafting from the feed text", urls[0], clip(evidence.error, 120)
            )
            return
        typed = [r for r in self._indicator_records if r.role != "unknown" or r.status != "unknown"]
        historical = [r.value for r in self._indicator_records if r.status == "historical"]
        self.trail.step(
            "source",
            "%s (%d chars, %d chunk(s)) in %.0fs: %d artifact(s) verified, %d dropped; "
            "%d/%d indicator(s) typed; historical: %s",
            urls[0],
            evidence.chars,
            evidence.chunks,
            self.trail.elapsed - started,
            len(evidence.artifacts),
            len(evidence.dropped),
            len(typed),
            len(self._indicator_records),
            listing(historical, "none"),
        )
        self._read_detection_guidance(evidence)

    def _observed_commands(self, item: CTIItem, platforms: list[str]) -> list[dict[str, Any]]:
        """Commands the source shows being run, each a process-rule candidate."""
        from hecate_agent.core.command_rules import command_candidates
        from hecate_agent.core.technique_evidence import extract_primary_actor

        primary_actor = (
            extract_primary_actor(self._primary_evidence_text(item))
            or attributed_actor(item.content)
            or None
        )
        candidates: list[dict[str, Any]] = list(
            command_candidates(
                self._primary_evidence_text(item), platforms, primary_actor=primary_actor
            )
        )
        if candidates:
            self.trail.step(
                "sigma",
                "%d command(s) the source shows being run: %s",
                len(candidates),
                listing([str(c.get("title", "")) for c in candidates]),
            )
        return candidates

    def _source_artifacts(self) -> list[dict[str, Any]]:
        """The primary source's verified artifacts, for two-pass Sigma generation."""
        from dataclasses import asdict

        if self._source_evidence is None:
            return []
        return [asdict(a) for a in getattr(self._source_evidence, "artifacts", []) or []]

    def _log_query_literals(self, artifacts: list[dict[str, Any]], platforms: list[str]) -> None:
        """Pass one of rule generation: the exact values rules may match."""
        from hecate_agent.core.query_literals import literals_from_artifacts

        literals = literals_from_artifacts(artifacts, platforms)
        if literals:
            self.trail.step(
                "sigma",
                "pass 1: %d exact value(s) from the source rules may match: %s",
                len(literals),
                listing([lit.sigma for lit in literals]),
            )
        else:
            self.trail.step(
                "sigma", "pass 1: no verified source values; model rules are not held to a list"
            )

    def _log_rule_review(self, rules: list[dict[str, Any]], gaps: list[dict[str, str]]) -> None:
        """A2: what the reviewer said about each model rule, and what no rule covers."""
        if not self.settings.sigma_review_enabled:
            return
        import yaml

        verdicts: list[str] = []
        for rule in rules:
            try:
                review = (yaml.safe_load(str(rule.get("rule_yaml", ""))) or {}).get("hecate_review")
            except yaml.YAMLError:
                continue
            if review:
                verdicts.append(f"{rule.get('title', 'untitled')}: {review.get('verdict')}")
        self.trail.step(
            "review",
            "%d model rule(s) reviewed%s; %d uncovered behaviour(s)%s",
            len(verdicts),
            f" ({'; '.join(verdicts)})" if verdicts else "",
            len(gaps),
            f": {listing([g.get('behaviour', '') for g in gaps])}" if gaps else "",
        )

    def _audit_rule_provenance(self, rules: list[dict[str, Any]]) -> None:
        """Every address and hash a rule matches must say where it came from.

        Rules carry a ``hecate_provenance`` list (role, status, source and the
        typing passage per indicator). The generator already rejects invented
        indicators; an address or hash with no entry here means one slipped
        through, and the reviewer is told which.
        """
        import yaml

        traced = 0
        untraced: list[str] = []
        for rule in rules:
            try:
                document = yaml.safe_load(str(rule.get("rule_yaml", ""))) or {}
            except yaml.YAMLError:
                continue
            known = {
                str(e.get("value", "")).lower() for e in document.get("hecate_provenance") or []
            }
            traced += len(known)
            text = yaml.safe_dump(document.get("detection") or {}).lower()
            for value in set(_RULE_IOC_RE.findall(text)):
                if not any(value in k or k in value for k in known if k):
                    untraced.append(f"{value} ({rule.get('title', 'untitled')})")
        if untraced:
            self.trail.step(
                "provenance", "untraced indicator(s) in rules: %s", listing(sorted(untraced))
            )
            log.warning(
                "Sigma rules match indicators with no provenance: %s", ", ".join(sorted(untraced))
            )
        else:
            self.trail.step(
                "provenance",
                "%d indicator(s) across %d rule(s), each traced to its source",
                traced,
                len(rules),
            )

    def _specimen_platforms(self, item: CTIItem) -> list[str]:
        """Platforms the item and its primary source show in observed activity, with the markers logged."""
        from hecate_agent.core.platform_evidence import platform_evidence

        evidence = platform_evidence([self._primary_evidence_text(item)])
        self._platform_evidence = evidence.to_dict()
        supported: list[str] = list(evidence.supported)
        if supported:
            self.trail.step(
                "scope",
                "the specimen's evidence shows %s: %s",
                listing(supported),
                "; ".join(
                    f"{p} ({', '.join(m['marker'] for m in evidence.markers[p][:6])})"
                    for p in supported
                ),
            )
        elif evidence.markers:
            self.trail.step(
                "scope",
                "platform evidence too thin to scope on: %s",
                listing(sorted(evidence.markers)),
            )
        self._specimen = supported
        return supported

    def _read_detection_guidance(self, evidence: Any) -> None:
        """Extract the report's own detection guidance and log where each item can run."""
        from hecate_agent.core.detection_guidance import extract_guidance

        items = extract_guidance(
            getattr(evidence, "text", "") or "", getattr(evidence, "url", "") or ""
        )
        self._detection_guidance = [g.to_dict() for g in items]
        if not items:
            self.trail.step("guidance", "the source publishes no detection guidance section")
            return
        routes = Counter(g.route for g in items)
        candidates = sum(len(g.candidates) for g in items)
        self.trail.step(
            "guidance",
            "%d item(s) from the source: %s; %d Sigma candidate(s)",
            len(items),
            ", ".join(f"{n} {route}" for route, n in sorted(routes.items())),
            candidates,
        )

    def _grounding_section(
        self,
        req: DraftHuntRequest,
        item: CTIItem,
        technique_facts: dict[str, TechniqueFact] | None = None,
    ) -> str:
        """Audit the draft as it currently stands and render the result.

        Best-effort: an audit that raises must not cost a hunt that is
        otherwise complete, so a failure leaves the section empty rather than
        aborting the cycle.
        """
        # Audit the draft *without* its own previous Grounding section. The
        # section is re-rendered on the second pass (after Sigma), and feeding
        # a claim table back through the extractor would have the audit read
        # its own output as though it were hunt content.
        previous_section, req.grounding_section = req.grounding_section, ""
        try:
            draft_text = render_draft(req)
        finally:
            req.grounding_section = previous_section

        try:
            with self.metrics.measure("grounding_audit"):
                report = audit_draft(
                    draft_text=draft_text,
                    cti_text=self._primary_evidence_text(item),
                    research_text=self._evidence_research_text(req.research_id),
                    cti_techniques=[str(t) for t in (item.metadata.get("techniques") or [])],
                    technique_facts=technique_facts,
                    hunt_platforms=list(req.platforms),
                    matched_techniques=self._wording_matched,
                )
        except Exception as exc:
            log.warning("Grounding audit failed for %s (%s); section left empty.", req.hunt_id, exc)
            return ""

        tally = report.counts
        self.trail.step(
            "grounding",
            "%s: %d asserted by CTI, %d research-only, %d inferred, %d UNSUPPORTED%s",
            req.hunt_id,
            tally.get("asserted", 0),
            tally.get("corroborated", 0),
            tally.get("derived", 0),
            tally.get("unsupported", 0),
            f" ({listing(c.value for c in report.unsupported)})" if report.unsupported else "",
        )
        if report.unsupported:
            log.warning(
                "%s carries %d claim(s) that trace to no source: %s",
                req.hunt_id,
                len(report.unsupported),
                ", ".join(c.value for c in report.unsupported),
            )
        section: str = render_grounding_section(report)
        if self._unevidenced_dropped:
            section += (
                "\n> Dropped before drafting, because the model proposed them and nothing "
                "in the CTI or research describes them: "
                + ", ".join(f"`{t}`" for t in self._unevidenced_dropped)
                + "\n"
            )
        return section

    def _drop_unevidenced_techniques(
        self,
        techniques: list[str],
        protected: list[str],
        cti_text: str,
        research_text: str,
    ) -> list[str]:
        """Remove model-picked techniques that no source describes.

        The audit already flagged these, but only after they had been written
        to the frontmatter, turned into tactics, and used to tag Sigma rules:
        four of the five drafts on 25 Sep carried one (T1078 twice, T1053,
        T1059), and H-0013's only rule was tagged T1053 Scheduled Task on a
        DLL-hijacking hunt. Dropping them here, before any of that is derived,
        keeps a flagged guess from becoming the hunt's mapping.

        Techniques the intel supports (asserted, or matched in its wording)
        are never dropped, and nor is anything the matrix cannot resolve --
        the unknown-ID step handles those under its own name.
        """
        shielded = {t.upper() for t in protected}
        kept: list[str] = []
        self._unevidenced_dropped = []
        for technique_id in techniques:
            upper = technique_id.upper()
            if upper in shielded or upper.split(".")[0] in shielded:
                kept.append(technique_id)
                continue
            meta = self.hecate.lookup_technique(
                technique_id, timeout_sec=self.settings.llm_timeout_sec
            )
            names = tuple(n for n in (meta.name, meta.parent_name) if n)
            if meta.found and technique_lacks_evidence(upper, names, cti_text, research_text):
                self._unevidenced_dropped.append(f"{upper} {meta.name}".strip())
            else:
                kept.append(technique_id)
        if self._unevidenced_dropped:
            self.trail.step(
                "techniques",
                "dropped model picks no source describes: %s",
                listing(self._unevidenced_dropped),
            )
        return kept

    def _research_text(self, research_id: str | None) -> str:
        """The research document's text, so its cited sources also count as
        grounding for a claim the CTI itself did not make."""
        if not research_id:
            return ""
        path = self.settings.hecate_workspace / "research" / f"{research_id}.md"
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    def _attach_sigma_rules(
        self,
        req: DraftHuntRequest,
        path: Path,
        item: CTIItem,
        technique_facts: dict[str, TechniqueFact] | None = None,
    ) -> None:
        """Draft Sigma rules for the hunt and rewrite the draft to include them.

        Techniques are the hunt's final list: the CTI's own (all of them, not
        the two or three the hypothesis reasoned about), then those matched in
        the intel's wording, then the model's -- already validated against
        ATT&CK and the hunt's platform. Reading the CTI's raw list instead
        drafted H-0011 (DNS exfiltration) from T1438 alone, a Mobile ATT&CK ID
        the cycle had just dropped, so the log sources fell back to
        process_creation and the T1071.004 that belonged there was ignored.
        """
        techniques = list(req.hypothesis.techniques)
        indicators = dict(item.metadata.get("indicators") or {})
        records = [r.to_dict() for r in self._indicator_records]
        if records:
            # The model may only use indicators a rule can observe; historical
            # hosts and in-memory hashes are then rejected as invented.
            from hecate_agent.core.provenance import routable_indicators

            indicators = routable_indicators(self._indicator_records)
        # Artifacts on the actor's own machine are not something this hunt can observe.
        source_observables = (
            [a.value for a in self._source_evidence.behaviours if a.role != "attacker-side"]
            if self._source_evidence is not None
            else []
        )
        out_dir = self.settings.hecate_workspace / "queries" / req.hunt_id

        payload = {
            "hunt_id": req.hunt_id,
            "threat_intel": item.content,
            "hypothesis": req.hypothesis.hypothesis,
            "justification": req.hypothesis.justification,
            "techniques": techniques,
            "platforms": req.platforms,
            "indicators": indicators,
            "references": [item.source_url] if item.source_url else [],
            # The draft's observables and ABLE evidence carry what grounded
            # research found -- H-0002's `nvidia-sysruntime.exe` -- which the
            # generator otherwise never sees, so it invented `.nvidia.exe`.
            "observables": [
                o
                for o in [*req.hypothesis.observables, req.hypothesis.evidence, *source_observables]
                if o and o.strip()
            ],
            "indicator_records": records,
            "detection_guidance": self._detection_guidance,
            "source_artifacts": self._source_artifacts(),
            "review_rules": self.settings.sigma_review_enabled,
            "observed_commands": self._observed_commands(item, req.platforms),
        }
        import json

        payload_str = json.dumps(payload)
        input_tokens = measure_tokens(
            payload_str, model_name=self.settings.hecate_llm_model or "gpt-4"
        )
        log.info(
            "Context Window Metrics: Executing sigma_generator with ~%d input tokens", input_tokens
        )

        self._log_query_literals(self._source_artifacts(), req.platforms)
        self.trail.step(
            "sigma",
            "drafting rules from techniques %s, indicator types %s, platforms %s",
            listing(techniques),
            listing(indicators.keys()),
            listing(req.platforms, "unscoped"),
        )
        sigma_started = self.trail.elapsed
        try:
            with self.metrics.measure("sigma_generation") as measured:
                result = self.hecate.sigma_generator(
                    payload, out_dir, timeout_sec=self.settings.sigma_timeout_sec
                )
                measured.set_usage(result.usage)
                if not result.success or not result.rules:
                    measured.set_status("partial")
        except HecateError as exc:
            self.trail.step(
                "sigma",
                "no rules after %.0fs: %s",
                self.trail.elapsed - sigma_started,
                clip(str(exc), 160),
            )
            log.warning(
                "Sigma drafting failed for %s (%s); draft keeps its placeholder query section.",
                req.hunt_id,
                exc,
            )
            return

        # A rejected rule is not retried, so its reason is the only record of
        # why a log source came back empty. Actual rejections are logged as warnings
        # and tallied in the trail; unsupported/omitted candidate categories are logged
        # as debug notes rather than rejected rules.
        real_rejections = [
            r for r in result.rejected
            if "no rule returned" not in r and "unsupported" not in r
        ]
        omitted = getattr(result, "omitted", []) or [
            r for r in result.rejected
            if "no rule returned" in r or "unsupported" in r
        ]
        for reason in real_rejections:
            self.trail.step("sigma", "rejected %s", clip(reason, 160))
            log.info("Sigma rule rejected for %s: %s", req.hunt_id, reason)
        for note in omitted:
            log.debug("Sigma log source omitted for %s: %s", req.hunt_id, note)

        self.trail.step(
            "sigma",
            "done in %.0fs: %d rule(s) kept (%s), %d rejected",
            self.trail.elapsed - sigma_started,
            len(result.rules or []),
            listing(sorted({str(r.get("logsource_category")) for r in result.rules or []})),
            len(real_rejections),
        )

        self._audit_rule_provenance(result.rules or [])
        self._log_rule_review(result.rules or [], result.review_gaps)

        if not result.success or not result.rules:
            log.warning(
                "Sigma drafting produced no usable rules for %s (%s); draft keeps its placeholder query section.",
                req.hunt_id,
                result.error or "no rules returned",
            )
            return

        for warning in result.warnings:
            if "no rule returned" in warning or "unsupported" in warning:
                log.debug("Sigma drafting note for %s: %s", req.hunt_id, warning)
            else:
                log.info("Sigma drafting note for %s: %s", req.hunt_id, warning)

        req.sigma_rules = result.rules
        req.review_gaps = result.review_gaps
        try:
            req.sigma_rule_dir = str(out_dir.relative_to(self.settings.hecate_workspace))
        except ValueError:  # out_dir outside the workspace -- show it whole
            req.sigma_rule_dir = str(out_dir)

        # Re-audit: the rules just added are themselves claims, and a rule
        # matching a C2 domain no source mentions is exactly what the audit
        # exists to surface.
        req.grounding_section = self._grounding_section(req, item, technique_facts)
        try:
            atomic_write_text(path, render_draft(req))
        except OSError as exc:
            log.warning(
                "Generated %d Sigma rule(s) for %s but could not rewrite the draft (%s); "
                "the rule files are still at %s.",
                len(result.rules),
                req.hunt_id,
                exc,
                out_dir,
            )
            return

        log.info(
            "Attached %d Sigma rule(s) to %s covering %s",
            len(result.rules),
            req.hunt_id,
            ", ".join(sorted({str(r.get("logsource_category")) for r in result.rules})),
        )

    def _resolve_ttps(
        self,
        techniques: list[str],
        scope_text: str = "",
        facts: dict[str, TechniqueFact] | None = None,
        protected: list[str] | None = None,
        intel_text: str = "",
        asserted: list[str] | None = None,
        specimen: list[str] | None = None,
    ) -> tuple[list[str], list[str]]:
        """Derive real tactics/platforms for a hypothesis's techniques.

        ``specimen`` is the platforms the specimen's own evidence shows
        (hecate_agent.core.platform_evidence). When set it outranks the
        hypothesis: H-0618's Location said "Linux and Windows workstations"
        for a Windows-only chain, and the hunt was scoped to both.

        ``intel_text`` (the CTI and research tradecraft) scopes the hunt when
        the hypothesis names no platform: what the intel names or implies
        outranks the union of everywhere the techniques could run.

        ``asserted`` are the protected techniques the CTI itself listed; they
        may add any platform they run on. The rest of ``protected`` were
        matched in the intel's wording, and add only platforms the intel names
        or implies. Omitted, every protected technique counts as asserted.

        ``protected`` are techniques the intelligence itself supports -- ones
        the CTI asserted or whose names its wording uses. The hypothesis's
        platform claim can drop a technique the *model* chose, never one of
        these; when one runs on a platform the hypothesis did not name, that
        platform is added instead.

        Looks each technique up against live ATT&CK data instead of
        hardcoding a fixed tactic/platform onto every draft regardless of
        what the CTI actually described. Order-preserving de-dup across
        techniques; a technique that fails to resolve (unknown ID, STIX
        unavailable) just contributes nothing rather than raising.

        Platforms from a near-universal technique (see
        `_NON_SCOPING_PLATFORM_THRESHOLD`) are excluded from the union: they
        carry no scoping signal and, unioned in, silently swamp genuinely
        narrow techniques also present on the same hypothesis. Tactics
        aren't filtered the same way -- a technique's tactic (e.g.
        "persistence") stays meaningful and low-cardinality even when its
        platform list is broad. If every resolved technique happens to be
        broad, `platforms` comes back empty and stays empty in the draft's
        frontmatter -- an honest gap signal rather than a fabricated
        full-platform list.
        """
        tactics: list[str] = []
        platforms: list[str] = []
        for technique_id in techniques:
            meta = self.hecate.lookup_technique(
                technique_id, timeout_sec=self.settings.llm_timeout_sec
            )
            # Record what the matrix said so the grounding audit can call out
            # an invented ID without paying for these subprocess lookups twice.
            if facts is not None:
                facts[technique_id.upper()] = TechniqueFact(
                    valid=meta.found,
                    superseded_by=(meta.superseded_from and meta.technique_id) or "",
                    names=tuple(n for n in (meta.name, meta.parent_name) if n),
                    # Relabelled to the frontmatter vocabulary so the audit can
                    # compare them against the hunt's own platform list. A
                    # near-universal technique records nothing: it carries no
                    # scoping signal, so it must not be able to contradict one.
                    platforms=(
                        ()
                        if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD
                        else tuple(_PLATFORM_LABELS.get(pf, pf) for pf in meta.platforms)
                    ),
                )
            for tactic in meta.tactics:
                if tactic not in tactics:
                    tactics.append(tactic)
            if len(meta.platforms) >= _NON_SCOPING_PLATFORM_THRESHOLD:
                continue
            for platform in meta.platforms:
                platform = _PLATFORM_LABELS.get(platform, platform)
                if platform not in platforms:
                    platforms.append(platform)

        # A hypothesis that names its platforms outranks the union. Unioning
        # across every technique the CTI asserted is right for "where could
        # this technique occur" and wrong for "where does this hunt look":
        # it returned five platforms for a hypothesis whose own sentence said
        # "compromised Windows systems". Normally only narrows -- a claimed
        # platform that a source-asserted technique contradicts is ignored.
        claimed = platforms_named_in(scope_text)
        claimant = "the hypothesis"
        self._platform_dropped = set()
        shielded = {t.upper() for t in (protected or [])}
        self.trail.step(
            "scope",
            "techniques run on %s; hypothesis names %s",
            listing(platforms, "no narrow platform"),
            listing(claimed),
        )
        if specimen:
            unsupported = [p for p in claimed if p not in specimen]
            if unsupported:
                self.trail.step(
                    "scope",
                    "hypothesis names %s; the specimen's evidence shows only %s: not scoping to %s",
                    listing(claimed),
                    listing(specimen),
                    listing(unsupported),
                )
            kept = [p for p in claimed if p in specimen]
            if not kept:
                claimant = "the specimen's evidence"
            claimed = kept or list(specimen)
        # A hypothesis sentence often names no platform at all ("Adversaries
        # use phishing campaigns to deliver VB6 malware"), and the union of
        # everywhere its techniques run is then nearly every platform ATT&CK
        # has. The intel usually says, or shows by its artifacts, where the
        # activity happened.
        if not claimed and intel_text:
            claimed = platforms_evidenced_in(intel_text)
            claimant = "the intel"
            if claimed:
                self.trail.step("scope", "intel names or implies %s", listing(claimed))
        if claimed:
            scoped = [p for p in platforms if p in claimed]
            # If the resolved techniques have ZERO overlap with what was claimed
            # (e.g. LLM suggested T1207 Windows for a macOS hunt), the technique
            # is hallucinated. The claimed text is the source of truth.
            final_platforms = scoped if scoped else claimed
            if not scoped:
                self.trail.step(
                    "scope",
                    "no overlap: trusting %s (%s) over the techniques",
                    claimant,
                    listing(claimed),
                )
            elif scoped != platforms:
                self.trail.step("scope", "narrowed to what %s names: %s", claimant, listing(scoped))

            # Evidence-backed techniques first: they widen the platform list
            # rather than being dropped. H-0014's CTI said "PowerShell-based
            # collection and staging"; the hypothesis said "Linux servers";
            # T1059.001 was dropped and the hunt shipped with no techniques.
            #
            # A wording match widens only onto platforms the intel itself
            # names or implies. Matches are loose: H-0018 (a Teams vishing
            # campaign on Windows) matched T1546.005 Trap on a research source
            # title, and it added Linux and macOS. T1059.001 still widens
            # H-0014, since "PowerShell" is itself evidence of Windows.
            by_cti = shielded if asserted is None else {t.upper() for t in asserted}
            evidenced = platforms_evidenced_in(intel_text)
            if facts is not None:
                for tech_id, fact in facts.items():
                    if tech_id.split(".")[0] not in shielded and tech_id not in shielded:
                        continue
                    missing = [p for p in fact.platforms if p not in final_platforms]
                    if not fact.platforms or len(missing) != len(fact.platforms):
                        continue
                    if specimen and not any(p in specimen for p in missing):
                        self.trail.step(
                            "scope",
                            "not widening for %s: the specimen's evidence shows only %s",
                            tech_id,
                            listing(specimen),
                        )
                        continue
                    if specimen:
                        missing = [p for p in missing if p in specimen]
                    if tech_id not in by_cti and tech_id.split(".")[0] not in by_cti:
                        missing = [p for p in missing if p in evidenced]
                        if not missing:
                            self.trail.step(
                                "scope",
                                "not widening for %s: matched in the wording, but the intel "
                                "names none of %s",
                                tech_id,
                                listing(fact.platforms),
                            )
                            continue
                    final_platforms = [*final_platforms, *missing]
                    self.trail.step(
                        "scope",
                        "keeping %s (the intel names it): adding %s to the platforms",
                        tech_id,
                        listing(missing),
                    )

            # Mark any technique that strongly contradicts our final platforms as invalid
            # so it is stripped from the payload and doesn't pollute the Sigma generator
            if facts is not None:
                for tech_id, fact in facts.items():
                    if fact.platforms and not any(p in final_platforms for p in fact.platforms):
                        fact.valid = False
                        self._platform_dropped.add(tech_id)
                        self.trail.step(
                            "scope",
                            "%s only runs on %s: dropping it",
                            tech_id,
                            listing(fact.platforms),
                        )

            return tactics, final_platforms

        return tactics, platforms

    def _advance_past(self, item: CTIItem) -> bool:
        """Acknowledge an item so the cursor moves; False if it could not.

        Without the advance the same item is returned by the next call, so a
        caller that keeps looping would spin on it forever.
        """
        try:
            self.cti.acknowledge(item)
        except Exception as exc:  # provider-specific cursor failures
            log.warning("Could not advance past CTI item (%s); stopping this cycle.", exc)
            return False
        return True

    def _drafted_from_same_source(self, item: CTIItem) -> str | None:
        """The hunt already drafted from this item's source link, if any.

        H-0011 and H-0017 were both drafted from one MISP event (Kunai, open
        recursive DNS), a day apart, when the event reappeared on the feed.
        The second draft cost a research run and a review for nothing the
        first did not already say. Matched on the rendered references link,
        which every draft writes, so no separate index has to be kept in step.
        """
        url = item.source_url.strip()
        if not url:
            return None
        needle = f"]({url})"
        for path in sorted(self.settings.hunts_root.rglob("H-*.md")):
            try:
                if needle in path.read_text(encoding="utf-8"):
                    return path.stem
            except OSError:
                continue
        return None

    def _next_actionable_item(self) -> tuple[CTIItem | None, int, int]:
        """The next CTI item worth drafting, and how many were walked past, and how many parked.

        An item with neither narrative nor a parseable indicator inventory
        offers nothing to hunt. Drafted anyway it produced H-0630 --
        "Indicators published in Teaching AI to Reason Through Detection
        Triage appear in telemetry", a sweep for indicators that do not
        exist, off a vendor marketing post.

        Skipped items are acknowledged so the cursor advances past them
        instead of the same item being re-offered every cycle. This runs
        before the quota is reserved: walking past an item is not a draft and
        must not cost one.
        """
        skipped = 0
        parked_count = 0
        for _ in range(_MAX_SKIPS_PER_CYCLE + 1):
            item = self.cti.next_item()
            if item is None:
                self.trail.step("intake", "queue empty")
                return None, skipped, parked_count
            self.trail.step(
                "intake",
                '%s: "%s" (%d chars; indicators: %s; CTI techniques: %s)%s',
                item.source,
                clip(item.title or (item.content.splitlines() or [""])[0], 80),
                len(item.content),
                counts(item.metadata.get("indicators") or {}),
                listing(item.metadata.get("techniques") or []),
                (
                    f"; {item.metadata['backlog']} high-signal waiting in its backlog"
                    if "backlog" in item.metadata
                    else ""
                ),
            )
            if is_actionable(item.content):
                verdict = triage(item) if self.settings.cti_triage == "park" else None
                if verdict is not None and verdict.park:
                    reason = verdict.reason
                else:
                    earlier = (
                        self._drafted_from_same_source(item)
                        if self.settings.cti_triage == "park"
                        else None
                    )
                    if earlier is None:
                        self.trail.step(
                            "triage",
                            "pass (%s)",
                            "triage off"
                            if verdict is None
                            else "no commentary category or title shape",
                        )
                        return item, skipped, parked_count
                    reason = (
                        f"already drafted as {earlier} from the same source ({item.source_url})"
                    )
                self.trail.step("triage", "park: %s", reason)
                # Held back, not dropped: the cursor has already moved past
                # this item, so the copy written here is the only one left.
                skipped += 1
                parked_count += 1
                log.info(
                    "Parking CTI item from %s (%s): %s",
                    item.source,
                    item.title[:60] or "untitled",
                    reason,
                )
                try:
                    park(self.settings.cti_queue_dir_resolved, item, reason)
                except OSError as exc:
                    # Parking is the whole safety net. If it cannot be written,
                    # draft the item rather than losing it.
                    log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                    parked_count -= 1
                    return item, skipped - 1, parked_count
                if not self._advance_past(item):
                    return None, skipped, parked_count
                continue

            # Counted where the decision is made, not after the cursor moves:
            # an item we could not advance past was still found and rejected,
            # and reporting "no CTI in queue" for it would be untrue.
            skipped += 1
            self.trail.step("triage", "skip: no narrative, no indicator inventory, no prose")
            log.info(
                "Skipping CTI item from %s: no narrative, no parseable indicator "
                "inventory and no free-form prose, so there is nothing to hunt.",
                item.source,
            )
            if not self._advance_past(item):
                return None, skipped, parked_count

        log.info("Found %d non-actionable CTI items; stopping this cycle.", skipped)
        return None, skipped, parked_count

    def _run_body(self, state: OrchestratorState, *, dry_run: bool) -> RunResult:
        # Primary-source evidence for this cycle's item; see _gather_source_evidence.
        self._source_evidence = None
        self._enriched_context = ""
        self._indicator_records = []
        self._detection_guidance = []
        self._specimen = []
        self._platform_evidence = {}
        self._research_grounding = ""
        self._research_grounding_label = ""
        self._technique_evidence = []
        self._claim_audit = []
        with self.metrics.measure("cti_intake"):
            item, skipped, parked_count = self._next_actionable_item()
        if item is None:
            if skipped:
                log.info("No actionable CTI this cycle; %d item(s) had nothing to hunt.", skipped)
                return RunResult(
                    outcome="no_actionable_cti",
                    detail=f"skipped {skipped}",
                    parked_count=parked_count,
                )
            log.info("No CTI in queue; nothing to do this cycle.")
            return RunResult(outcome="no_cti", parked_count=parked_count)

        log.info("Picked up CTI item from %s (%d chars)", item.source, len(item.content))
        self.metrics.set_source(item.source, item.identifier)

        if not state.check_and_reserve_draft(self.settings.max_drafts_per_day):
            log.warning(
                "Daily draft quota reached (%d). Leaving CTI in queue for next cycle.",
                self.settings.max_drafts_per_day,
            )
            self.trail.step("quota", "daily draft quota full; item stays queued")
            return RunResult(
                outcome="quota_reached",
                detail=f"{state.drafts_today}/{self.settings.max_drafts_per_day}",
            )
        self.trail.step(
            "quota",
            "draft slot %d/%d reserved",
            state.drafts_today,
            self.settings.max_drafts_per_day,
        )

        if dry_run:
            log.info("[dry-run] Would call hecate and write a draft; leaving CTI in queue.")
            state.drafts_today -= 1  # reverse the reservation in dry-run
            state.total_drafts_ever -= 1
            return RunResult(
                outcome="dry_run", detail=item.content[:100], parked_count=parked_count
            )

        # Computed once for the whole cycle: the same "is there any prose
        # here?" answer gates web search during research (nothing real to
        # search for) and constrains hypothesis generation afterwards
        # (nothing real to infer a behavior from).
        intel_has_narrative = has_narrative(item.content)
        if not intel_has_narrative:
            log.info(
                "CTI item has no narrative (bare IOC dump); disabling web search and "
                "constraining the hypothesis to indicator presence for this cycle."
            )

        # A narrative-free dump whose indicator inventory we can actually read
        # gets a deterministic sweep draft below -- no LLM call, so no slot for
        # the model to invent a delivery vector or technique into.
        #
        # Both halves of that condition matter. `has_narrative` is a
        # heuristic over provider blurb formats, and if it were wrong on its
        # own, building the draft from a template would *discard* real
        # narrative CTI -- a worse failure than the fabrication this fixes.
        # Requiring a parseable inventory as well means we act only on
        # positive evidence that this really is a feed dump; anything else
        # falls through to the LLM with the indicators-only constraint,
        # which degrades safely either way.
        #
        # Computed here, ahead of research, because it now also decides
        # whether research runs at all.
        sweep_inventory = {} if intel_has_narrative else parse_indicator_inventory(item.content)
        if sweep_inventory:
            route = "indicator dump -> deterministic sweep draft (no research, no LLM)"
        elif not self.settings.research_enabled:
            route = "research disabled -> ungrounded hypothesis"
        elif intel_has_narrative:
            route = "narrative -> research with web search -> hypothesis"
        else:
            route = "no narrative -> research without web search -> indicator-only hypothesis"
        self.trail.step("route", "%s", route)

        # Only a narrative search spends Tavily credits, so only that counts.
        # Refused rather than drafted ungrounded, for the same reason a
        # research failure is: the CTI waits for tomorrow's quota. Checked
        # ahead of the source read, which is minutes of model time that a
        # refused cycle would throw away.
        if (
            not sweep_inventory
            and self.settings.research_enabled
            and intel_has_narrative
            and not state.check_and_reserve_research(self.settings.max_research_runs_per_day)
        ):
            log.warning(
                "Daily research quota reached (%d). Leaving CTI in queue for next cycle.",
                self.settings.max_research_runs_per_day,
            )
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(
                outcome="research_quota_reached",
                detail=f"{state.research_runs_today}/{self.settings.max_research_runs_per_day}",
                parked_count=parked_count,
            )

        # The report the item links to carries what the feed summary drops:
        # process tree, paths, ports, and what each indicator is. H-0618 was
        # drafted from a 2,194-character blurb of a 32,920-character report.
        self._gather_source_evidence(item)
        source_block = (
            self._source_evidence.summary_block()
            if self._source_evidence is not None and self._source_evidence.artifacts
            else ""
        )

        # Enrich the CTI using external OSINT sources (VT, Shodan, Censys, ThreatFox, MISP)
        from hecate_agent.api import extract_indicators, generate_enrichment_summary

        log.info("Enriching CTI observables via OSINT sources...")
        try:
            indicators = extract_indicators(item.content)
            ips_count = len(indicators.get("ips", []))
            hashes_count = len(indicators.get("hashes", []))
            domains_count = len(indicators.get("domains", []))
            total_obs = ips_count + hashes_count + domains_count
            if total_obs:
                self.trail.step(
                    "enrichment",
                    "%d observable(s) (%d ip, %d hash, %d domain) checked via VT, GreyNoise, Shodan, Censys, ThreatFox",
                    total_obs,
                    ips_count,
                    hashes_count,
                    domains_count,
                )
                item_inds = item.metadata.setdefault("indicators", {})
                norm = {"ipv4": indicators.get("ips", []), "domain": indicators.get("domains", [])}
                for h in indicators.get("hashes", []):
                    htype = "sha256" if len(h) == 64 else ("sha1" if len(h) == 40 else "md5")
                    norm.setdefault(htype, []).append(h)
                for k, vs in norm.items():
                    item_inds.setdefault(k, [])
                    for v in vs:
                        if v not in item_inds[k]:
                            item_inds[k].append(v)

                from hecate_agent.core.provenance import records_from_cti

                cti_records = records_from_cti(norm)
                for rec in cti_records:
                    if not any(
                        e.value == rec.value and e.type == rec.type for e in self._indicator_records
                    ):
                        self._indicator_records.append(rec)
            else:
                self.trail.step("enrichment", "no observable IPs/hashes/domains in source")
        except Exception as exc:
            log.warning("Indicator extraction failed before enrichment: %s", exc)

        self._enriched_context = generate_enrichment_summary(item.content)

        intel_for_models = (
            f"{item.content}\n\n{source_block}\n\n{self._enriched_context}"
            if source_block
            else f"{item.content}\n\n{self._enriched_context}"
        )

        research_id: str | None = None
        related_hunts: list[str] = []
        if sweep_inventory:
            # `hecate-agent research new` on a bare indicator dump spends four skills
            # producing "insufficient information" boilerplate -- measured
            # across R-0604/R-0608/R-0610 at ~2 minutes and 4 LLM calls each
            # for a document with no findings, no telemetry mapping and no
            # techniques, which the draft then linked as "detailed pre-hunt
            # research". The sweep draft below is built from the indicator
            # inventory alone, so there is nothing for that call to ground.
            #
            # This keys off sweep_inventory rather than intel_has_narrative on
            # purpose: a narrative-free dump we could NOT parse still falls
            # through to the LLM hypothesis generator, and that path must stay
            # grounded (ungrounded generation measured ~30% accuracy).
            log.info("CTI is a parseable indicator dump; skipping research grounding.")
        elif self.settings.research_enabled:
            topic, technique = derive_research_topic(item.content, title=item.title or None)
            self.trail.step(
                "research",
                'starting: topic "%s"%s; web search %s; source text %d chars',
                clip(topic, 80),
                f", technique {technique}" if technique else "",
                "on" if intel_has_narrative else "off",
                len(intel_for_models),
            )
            research_started = self.trail.elapsed

            # Measure context usage for optimization. Research is sent the
            # CTI body as source_context as well as the topic, so count both.
            input_tokens = measure_tokens(
                f"{topic}\n{intel_for_models}", model_name=self.settings.hecate_llm_model or "gpt-4"
            )
            log.info(
                "Context Window Metrics: Executing research_new with ~%d input tokens", input_tokens
            )

            try:
                with self.metrics.measure("research") as measured:
                    research_result = self.hecate.research_new(
                        topic=topic,
                        technique=technique,
                        depth=self.settings.research_depth,
                        timeout_sec=self.settings.llm_timeout_sec,
                        web_search_enabled=intel_has_narrative,
                        # The topic is a search label; research needs the report,
                        # and the primary source's verified artifacts with it.
                        source_context=intel_for_models,
                    )
                    measured.set_usage(research_result.usage)
            except HecateError as exc:
                # Cold (ungrounded) generation measured ~30% accuracy on known-
                # answer fixtures (see `hecate-agent eval`) — a research failure is
                # refused rather than silently falling back to that. Refund
                # the quota; the CTI stays in the queue for the next cycle.
                log.error(
                    "hecate-agent research new failed (%s); refusing to generate an ungrounded hypothesis",
                    exc,
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(
                    outcome="research_error", detail=str(exc), parked_count=parked_count
                )

            if research_result.is_empty:
                log.error(
                    "hecate-agent research new produced no research_id; refusing to generate an ungrounded hypothesis"
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="research_empty", parked_count=parked_count)

            research_id = research_result.research_id
            related_hunts = research_result.related_hunts
            self._research_grounding = research_result.grounding
            self._research_grounding_label = research_result.grounding_label()
            self.trail.step(
                "research",
                "%s done in %.0fs; grounding: %s; describes adversary behavior: %s; related hunts: %s",
                research_id,
                self.trail.elapsed - research_started,
                self._research_grounding_label,
                "yes" if research_result.describes_behavior else "NO",
                listing(related_hunts),
            )
            if intel_has_narrative and research_result.grounding == "source-only":
                # Not parked: the item is still actionable. Research is just
                # not allowed to stand in for evidence it never gathered.
                log.warning(
                    "Research %s ran source-only (%s); it will not count as evidence for techniques or grounding.",
                    research_id,
                    research_result.web_search_note or "no web searches",
                )
                self.trail.step(
                    "research",
                    "SOURCE-ONLY: web search was requested but none succeeded; "
                    "research is not counted as evidence this cycle",
                )

            # Intake triage matches publisher categories and title shapes, so
            # it cannot see that a post with a fresh category is commentary:
            # an Elastic product blog ("AI & Automation") and a Talos opinion
            # piece ("On The Radar") both became drafts (H-0005, H-0006), and
            # research had already said of each "the source describes no
            # behavior to detect". Only prose items: a bare dump describes no
            # behavior by definition and still makes an indicator hunt.
            if (
                self.settings.cti_triage == "park"
                and intel_has_narrative
                and not research_result.describes_behavior
            ):
                reason = (
                    f"research {research_id} found no adversary behavior to hunt in it "
                    "(commentary, product or opinion content)"
                )
                try:
                    park(self.settings.cti_queue_dir_resolved, item, reason)
                except OSError as exc:
                    log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                else:
                    self.trail.step("research", "park: %s; draft slot refunded", reason)
                    log.info(
                        "Parking CTI item from %s (%s): %s",
                        item.source,
                        item.title[:60] or "untitled",
                        reason,
                    )
                    # The draft slot was reserved for a hunt that will not be
                    # written; the research run was real and stays counted.
                    state.drafts_today -= 1
                    state.total_drafts_ever -= 1
                    self._advance_past(item)
                    return RunResult(
                        outcome="parked_after_research",
                        detail=reason,
                        research_id=research_id,
                        parked_count=parked_count + 1,
                    )

            log.info("Research %s grounds this cycle's hypothesis", research_id)

        if sweep_inventory:
            log.info(
                "CTI is an indicator dump (%d indicators, %d type(s)); building a sweep "
                "draft directly instead of generating a behavioral hypothesis.",
                sum(sweep_inventory.values()),
                len(sweep_inventory),
            )
            hypothesis = build_indicator_sweep(item.content, title=item.title or None)
        else:
            self.trail.step(
                "hypothesis",
                "asking the model%s%s",
                f" (grounded by {research_id})" if research_id else " (no research)",
                "" if intel_has_narrative else "; constrained to indicator presence",
            )
            hypothesis_started = self.trail.elapsed
            # Measure context usage for optimization
            input_tokens = measure_tokens(
                item.content, model_name=self.settings.hecate_llm_model or "gpt-4"
            )
            log.info(
                "Context Window Metrics: Executing hypothesis_generator with ~%d input tokens",
                input_tokens,
            )
            try:
                with self.metrics.measure("hypothesis_generation") as measured:
                    hypothesis = self.hecate.hypothesis_generator(
                        threat_intel=intel_for_models,
                        research_id=research_id,
                        timeout_sec=self.settings.llm_timeout_sec,
                        indicators_only=not intel_has_narrative,
                    )
                    measured.set_usage(hypothesis.usage)
                    if hypothesis.fallback:
                        measured.set_status("partial")
            except HecateError as exc:
                log.error("hecate hypothesis-generator failed: %s", exc)
                # Refund the quota — the CTI stays in the queue.
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                return RunResult(outcome="hecate_error", detail=str(exc), parked_count=parked_count)

        repaired = _fill_empty_source_slot(hypothesis.hypothesis, item.title)
        if repaired != hypothesis.hypothesis:
            log.info("Filled empty [source] slot in indicator-sweep hypothesis from CTI title.")
            hypothesis.hypothesis = repaired

        if getattr(hypothesis, "indicator_records", None):
            from hecate_agent.core.provenance import IndicatorRecord

            added = 0
            for r in hypothesis.indicator_records:
                try:
                    if "source" not in r:
                        r["source"] = "cti"
                    rec = IndicatorRecord.from_dict(r)
                    if not any(
                        e.value == rec.value and e.type == rec.type for e in self._indicator_records
                    ):
                        self._indicator_records.append(rec)
                        added += 1
                except Exception as exc:
                    log.warning("Failed to parse indicator record from hypothesis: %s", exc)
            if added > 0:
                log.info("Appended %d structured indicator(s) from hypothesis extraction.", added)

        if not sweep_inventory:
            self.trail.step(
                "hypothesis",
                'done in %.0fs: "%s"',
                self.trail.elapsed - hypothesis_started,
                clip(hypothesis.hypothesis, 140),
            )
            if not hypothesis.is_threat_report:
                why = clip(hypothesis.low_confidence_reason, 120) or "no reason given"
                self.trail.step("hypothesis", "model judged this NOT a threat report: %s", why)

                # A last gate for commentary that research let through: the
                # hypothesis model reads the item whole and says outright when
                # no adversary did anything. Parked, not dropped, so a wrong
                # call costs one `parked restore`.
                if self.settings.cti_triage == "park":
                    reason = f"hypothesis model judged this NOT a threat report: {why}"
                    try:
                        park(self.settings.cti_queue_dir_resolved, item, reason)
                    except OSError as exc:
                        log.warning("Could not park CTI item (%s); drafting it instead.", exc)
                    else:
                        self.trail.step("hypothesis", "park: %s; draft slot refunded", reason)
                        log.info(
                            "Parking CTI item from %s (%s): %s",
                            item.source,
                            item.title[:60] or "untitled",
                            reason,
                        )
                        state.drafts_today -= 1
                        state.total_drafts_ever -= 1
                        # Without the acknowledgement the parked item stayed at
                        # the head of the queue: re-researched and re-parked
                        # every cycle, and -- since multi-provider rotation only
                        # advances on acknowledge -- nothing else drafted.
                        self._advance_past(item)
                        return RunResult(
                            outcome="parked_after_hypothesis",
                            detail=reason,
                            research_id=research_id,
                            parked_count=parked_count + 1,
                        )
        model_techniques = list(hypothesis.techniques)

        if hypothesis.is_empty:
            log.warning("hecate returned empty hypothesis; refunding quota and leaving CTI.")
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="empty_hypothesis", parked_count=parked_count)

        # Restore what the pipeline was discarding before the draft is built.
        # The hypothesis agent returns only the techniques it reasoned about,
        # generalised (T1059.003 -> T1059); the CTI asserted the full, precise
        # list. Merging is what keeps the draft's ATT&CK mapping, its platform
        # scope and its telemetry list faithful to the source.
        cti_techniques = [str(t) for t in (item.metadata.get("techniques") or [])]

        # Techniques whose names the intel itself uses as a phrase. Offered to
        # the model as a prompt hint first, which it ignored in 3 of 4 re-drafts
        # (SEO Poisoning offered, T1098/T1563 chosen), so they are now merged
        # in directly, after what the CTI asserted and ahead of the model's own
        # picks. An indicator dump gets none: it describes no behaviour.
        candidates: list[tuple[str, str]] = []
        self._wording_matched = []
        self._unevidenced_dropped = []
        if not sweep_inventory:
            # Research links are stripped: they cite retrieved pages, and a
            # page title is not the intel ("OAuth Traps" proposed T1546.005).
            with self.metrics.measure("technique_candidates"):
                candidates = self.hecate.candidate_techniques(
                    "\n".join(
                        [
                            item.content,
                            _LINK_RE.sub(
                                " ", research_tradecraft_text(self._research_text(research_id))
                            ),
                        ]
                    )
                )
            self.trail.step(
                "techniques",
                "matched in the intel's wording: %s",
                listing(f"{tid} {name}" for tid, name in candidates),
            )
        self._wording_matched = [tid for tid, _ in candidates]
        # Described behaviour, not just ATT&CK's names: "sandbox detection, CPU
        # checks, and sleep-timer evasion" is T1497 though no name appears.
        # Only observed use proposes a technique; a tool's capability does not.
        behaviour: list[Any] = []
        evidence_texts = self._evidence_texts(item, research_id)
        if not sweep_inventory:
            from hecate_agent.core.technique_evidence import map_behaviours

            behaviour = map_behaviours(evidence_texts)
            observed = [e.technique_id for e in behaviour if e.status == "observed"]
            self.trail.step(
                "techniques",
                "described behaviour observed: %s; capability only: %s",
                listing(observed),
                listing(e.technique_id for e in behaviour if e.status == "capability"),
            )
            self._wording_matched = list(dict.fromkeys([*self._wording_matched, *observed]))
        observed_ids = [e.technique_id for e in behaviour if e.status == "observed"]
        with self.metrics.measure("technique_validation"):
            hypothesis.techniques = merge_techniques(
                [*cti_techniques, *(tid for tid, _ in candidates), *observed_ids],
                hypothesis.techniques,
            )
        self.trail.step(
            "techniques",
            "model chose %s; CTI asserted %s -> merged %s",
            listing(model_techniques),
            listing(cti_techniques),
            listing(hypothesis.techniques),
        )
        with self.metrics.measure("technique_validation"):
            hypothesis.techniques = self._drop_unevidenced_techniques(
                hypothesis.techniques,
                protected=[*cti_techniques, *(tid for tid, _ in candidates), *observed_ids],
                cti_text=self._primary_evidence_text(item),
                # Links stripped, as for the candidates above: a cited page title
                # is not the intel. "OAuth Traps" in R-0018's sources kept T1546.005
                # Trap on a Teams vishing hunt.
                research_text=_LINK_RE.sub(" ", self._evidence_research_text(research_id)),
            )

            if not sweep_inventory:
                hypothesis.techniques = self._gate_on_observed_use(
                    hypothesis.techniques, cti_techniques, behaviour, evidence_texts
                )

        indicator_types = list((item.metadata.get("indicators") or {}).keys())
        for source in derive_data_sources(hypothesis.techniques, indicator_types):
            if source not in hypothesis.data_sources:
                hypothesis.data_sources.append(source)

        technique_facts: dict[str, TechniqueFact] = {}
        with self.metrics.measure("attack_lookup"):
            tactics, platforms = self._resolve_ttps(
                hypothesis.techniques,
                scope_text=" ".join([hypothesis.hypothesis, hypothesis.location]),
                facts=technique_facts,
                protected=[*cti_techniques, *(tid for tid, _ in candidates), *observed_ids],
                asserted=cti_techniques,
                intel_text="\n".join(
                    [item.content, research_tradecraft_text(self._research_text(research_id))]
                ),
                specimen=self._specimen_platforms(item),
            )

        # Applied here rather than at merge time: the platform list only
        # exists once the techniques have resolved against the live matrix.
        hypothesis.data_sources = platform_consistent_data_sources(
            hypothesis.data_sources, platforms
        )
        self.trail.step(
            "scope",
            "platforms %s; tactics %s; data sources %s",
            listing(platforms, "unscoped"),
            listing(tactics),
            listing(hypothesis.data_sources),
        )

        # An empty section is honest; a section listing the telemetry
        # categories back is not, and a reviewer skims past it as done.
        kept_observables = substantive_observables(hypothesis.observables)
        if kept_observables != hypothesis.observables:
            log.info(
                "Dropped %d observable(s) that restated a telemetry category or were templates",
                len(hypothesis.observables) - len(kept_observables),
            )
        hypothesis.observables = kept_observables or [_NO_OBSERVABLES]

        # 4.2 Drop unresolvable technique IDs from the draft so they don't
        # reach the frontmatter and break `hunt validate` downstream.
        kept_techniques = [
            t
            for t in hypothesis.techniques
            if t.upper() not in technique_facts or technique_facts[t.upper()].valid
        ]
        # Platform drops were already explained at the scope step; only IDs
        # the matrix does not know are reported here, under the right name.
        unknown = [
            t
            for t in hypothesis.techniques
            if t not in kept_techniques and t.upper() not in self._platform_dropped
        ]
        if unknown:
            self.trail.step("techniques", "dropped IDs not in ATT&CK: %s", listing(unknown))
        hypothesis.techniques = kept_techniques
        self._audit_claims(hypothesis, self._primary_evidence_text(item), platforms)

        # Nothing left to hunt: no technique survived the evidence and matrix
        # checks, and the intel published no indicator to sweep for. H-0005,
        # H-0006 and H-0014 reached review with an empty ATT&CK mapping;
        # H-0014 still carried 18 indicators and made a useful sweep, the
        # other two carried nothing and were closed unread.
        if (
            self.settings.cti_triage == "park"
            and not hypothesis.techniques
            and not sweep_inventory
            and not (item.metadata.get("indicators") or {})
        ):
            reason = "no ATT&CK technique survived grounding and the intel names no indicators"
            try:
                park(self.settings.cti_queue_dir_resolved, item, reason)
            except OSError as exc:
                log.warning("Could not park CTI item (%s); drafting it instead.", exc)
            else:
                self.trail.step("techniques", "park: %s; draft slot refunded", reason)
                log.info(
                    "Parking CTI item from %s (%s): %s",
                    item.source,
                    item.title[:60] or "untitled",
                    reason,
                )
                state.drafts_today -= 1
                state.total_drafts_ever -= 1
                self._advance_past(item)
                return RunResult(
                    outcome="parked_no_techniques",
                    detail=reason,
                    research_id=research_id,
                    parked_count=parked_count + 1,
                )

        if not hypothesis.actor.strip():
            attributed = attributed_actor(item.content)
            if attributed:
                self.trail.step("scope", "actor from the intel's attribution: %s", attributed)
                hypothesis.actor = attributed

        try:
            with hunt_id_lock(self.settings.hunts_root):
                hunt_id = next_hunt_id(self.settings.hunts_root)
                req = DraftHuntRequest(
                    hunt_id=hunt_id,
                    threat_intel=item.content,
                    hypothesis=hypothesis,
                    generated_at=datetime.now(UTC),
                    research_id=research_id,
                    tactics=tactics,
                    platforms=platforms,
                    source_url=item.source_url,
                    related_hunts=related_hunts,
                    source_evidence=(
                        self._source_evidence.to_dict() if self._source_evidence is not None else {}
                    ),
                    indicator_records=[r.to_dict() for r in self._indicator_records],
                    research_grounding=self._research_grounding_label,
                    technique_evidence=self._technique_evidence,
                    claim_audit=self._claim_audit,
                    detection_guidance=self._detection_guidance,
                )
                req.grounding_section = self._grounding_section(req, item, technique_facts)
                with self.metrics.measure("draft_write"):
                    path = write_draft(req, self.settings.hunts_root)
                self.trail.step("write", "%s written to %s", hunt_id, path)
        except OSError as exc:
            log.error("Failed to allocate/write draft hunt file: %s", exc)
            # Refund the quota — nothing was actually drafted, and the CTI
            # item is still unacknowledged so it stays queued for retry.
            state.drafts_today -= 1
            state.total_drafts_ever -= 1
            return RunResult(outcome="write_error", detail=str(exc), parked_count=parked_count)

        # Close the loop back to the research document. Isolated like the
        # other post-write steps: the draft already exists and its quota is
        # already spent, so a link failure is a warning, not a lost hunt.
        if research_id:
            try:
                self.hecate.link_research_to_hunt(
                    research_id, hunt_id, timeout_sec=self.settings.llm_timeout_sec
                )
            except HecateError as exc:
                log.warning(
                    "Could not link %s back to %s (%s); the hunt still records "
                    "spawned_from, so the forward reference is intact.",
                    hunt_id,
                    research_id,
                    exc,
                )

        # The draft file already exists on disk at this point. Acknowledge the
        # CTI item and save state *before* the multi-minute Sigma drafting
        # step, so if the process is killed during Sigma generation, we don't
        # lose the quota count and re-draft the exact same CTI item next cycle.
        try:
            self.cti.acknowledge(item)
            state.save(self.settings.state_file)
        except Exception as exc:  # isolate from the top-level guard
            log.warning(
                "Failed to acknowledge CTI item or save state after successfully drafting %s (%s); "
                "this item may be re-drafted under a new ID next cycle.",
                hunt_id,
                exc,
            )

        # Sigma drafting sits here deliberately: after the file exists, and
        # outside hunt_id_lock. It is a multi-minute LLM call, and holding
        # the ID-allocation lock across it would stall every concurrent
        # cycle behind it. The draft is rewritten in place once rules are
        # in hand, so a failure leaves the hunt standing with its
        # placeholder query section rather than losing it.
        if self.settings.sigma_generation_enabled:
            self._attach_sigma_rules(req, path, item, technique_facts)

        log.info(
            "Draft %s created at %s (research=%s, drafts today: %d/%d)",
            hunt_id,
            path,
            research_id or "none",
            state.drafts_today,
            self.settings.max_drafts_per_day,
        )

        result = RunResult(
            outcome="draft_created",
            hunt_id=hunt_id,
            draft_path=path,
            research_id=research_id,
        )

        # A notification failure must not turn an already-successful draft
        # into an "error" outcome — isolate it from the run_once() top-level
        # exception guard rather than letting it propagate.
        try:
            self.notify(result)
        except Exception as exc:  # notifications are best-effort, never fatal
            log.warning(
                "Draft-created notification failed (%s); draft %s was still created", exc, hunt_id
            )

        return result


# --- Factory ---------------------------------------------------------------


def build_default_orchestrator(settings: Settings) -> Orchestrator:
    """Wire up the standard orchestrator from settings alone."""
    hecate = HecateClient(
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
        env_overrides=settings.env_for_hecate(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    cti = get_provider(settings.cti_provider, settings=settings)
    notify = functools.partial(notify_draft_created, settings)
    return Orchestrator(settings=settings, hecate=hecate, cti_provider=cti, notify=notify)


def build_orchestrator_for_item(settings: Settings, item: CTIItem) -> Orchestrator:
    """The standard orchestrator, reading one supplied item in place of the configured feeds.

    Only intake differs from a scheduled cycle. Triage is off, since someone
    chose this item; the quotas, the drafting stages and every check after
    them are the cycle's own.
    """
    from hecate_runner.cti.single import SingleItemProvider

    settings = settings.model_copy(update={"cti_triage": "off"})
    hecate = HecateClient(
        hecate_bin=settings.hecate_bin_resolved,
        workspace=settings.hecate_workspace,
        env_overrides=settings.env_for_hecate(),
        default_timeout_sec=settings.llm_timeout_sec,
    )
    notify = functools.partial(notify_draft_created, settings)
    return Orchestrator(
        settings=settings, hecate=hecate, cti_provider=SingleItemProvider(item), notify=notify
    )
