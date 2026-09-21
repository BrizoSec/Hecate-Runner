"""Post-draft grounding audit: does every checkable claim trace to evidence?

Grounding in this pipeline is enforced at three points, and this module is the
third:

1. **Intake** decides what is worth hunting at all -- the galaxy/ATT&CK and
   org filters in the MISP provider, so a draft starts from a curated event
   rather than a feed dump.
2. **Generation** carries the evidence forward -- indicator values and the
   source's own technique list reach the model, research grounds on retrieved
   sources, and unsupported CVE claims are dropped before they reach a hunt.
3. **Audit** -- here -- re-reads the finished draft and asks, of each claim it
   can check, whether the source actually said it.

The audit is deliberately *reporting*, not blocking. A hunt that generalises
beyond its CTI is doing its job; the failure mode worth catching is a specific,
checkable assertion that no source supports, which reads exactly like evidence
to a reviewer. So claims are classified, not rejected:

Evidence is ranked, because not all of it is equally trustworthy. The CTI is
primary: a human or a feed published it, and it exists independently of this
pipeline. A research document is *secondary* -- it is model output, and
treating it as proof lets a fabrication launder itself. A CVE invented during
research and written into R-0611 would otherwise come back as "asserted" in
every hunt built from that research, which is circular and exactly backwards.

``asserted``
    The source CTI contains this verbatim. Primary evidence; safe to act on.
``corroborated``
    Absent from the CTI but present in the research document. Plausible, and
    the research cites real retrieved sources -- but the research is itself
    generated, so this is a claim about evidence rather than evidence.
``derived``
    Not in any source text, but legitimately inferable -- a technique the
    hypothesis reasoned to. Worth a reviewer's eye, not alarm.
``unsupported``
    Specific enough to be checked, checked, and absent from every source.
    This is the fabrication class: ``CVE-2024-1234`` asserted as fact, a
    Sigma rule matching a C2 domain that appears in no intelligence, or an
    ATT&CK technique ID that does not exist.

Only claim shapes that *should* be traceable are examined. A rule matching
``\\powershell.exe`` is behavioural and has no business being called
unsupported; a rule matching ``203.0.113.9`` does. The same rule governs
prose: an actor designator or a named malware family is a claim a source
either made or did not, while "adversaries use obfuscated commands" is the
interpretation a hunt exists to offer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Specific enough that an unsourced one is a fabrication rather than a
# generalisation. Deliberately excludes bare filenames and process names,
# which is what a behavioural rule is supposed to contain.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b", re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Hostnames that belong to the scaffolding rather than the intelligence:
#: the workspace's own MISP, documentation domains, and the RFC 2606 / RFC
#: 5737 reserved ranges that examples are written with. Flagging these as
#: fabricated indicators would train a reviewer to ignore the audit.
_SCAFFOLDING = frozenset(
    {
        "localhost",
        "example.com",
        "example.test",
        "example.org",
        "example.net",
        "attack.mitre.org",
        "github.com",
        "sigmahq.io",
    }
)

#: Suffixes that make a dotted token a filename, not a hostname. Without this
#: the domain pattern reads "svchost.exe" as a domain in the ".exe" TLD, and a
#: behavioural rule matching a process name would be reported as a fabricated
#: indicator -- the precise false alarm this audit must not produce.
_FILE_SUFFIXES = frozenset(
    {
        # Anything that is also a real TLD is deliberately absent: "com",
        # "sh", "md", "py" and "zip" all resolve, and skipping them would
        # silently exempt the most likely place for C2 to live from the one
        # check that would catch a fabricated domain. A genuine `.COM`
        # executable is rare enough to be worth the occasional stray row.
        "exe",
        "dll",
        "sys",
        "ps1",
        "bat",
        "cmd",
        "scr",
        "msi",
        "vbs",
        "js",
        "jar",
        "tmp",
        "dat",
        "log",
        "txt",
        "yml",
        "yaml",
        "json",
        "xml",
        "csv",
        "conf",
        "cfg",
        "ini",
        "rar",
        "docx",
        "xlsx",
        "pdf",
        "lnk",
        "hta",
        "iso",
        "img",
    }
)

#: Named entities are audited only in shapes precise enough to be worth
#: checking. Free-form proper-noun extraction is not viable here -- every
#: sentence-initial word and section heading is capitalised, and a section
#: full of false alarms teaches a reviewer to skip it, which costs more than
#: it catches. These three patterns cover the fabrication actually observed:
#: hypothesis generation inventing malware family names ("PureRAT and
#: Overlord RAT") that then propagated into a hunt file as if reported.
_ACTOR_DESIGNATOR_RE = re.compile(r"\b(?:APT|UNC|FIN|TA|TEMP)[-\s]?\d{2,5}\b", re.IGNORECASE)

#: Malware-category nouns, shared by the collocation pattern and the
#: all-caps sentence scan so the two cannot drift apart.
_MALWARE_CATEGORY = (
    "backdoor|ransomware|stealer|loader|trojan|implant|botnet|dropper|wiper|webshell|rat"
)

#: "<Name> backdoor", "<Name> ransomware" -- a capitalised token immediately
#: before a malware-category noun is a claim about a specific family.
#:
#: The capitalisation anchor is load-bearing, and must not sit under a global
#: ``re.IGNORECASE``: with one, ``[A-Z]`` matches lowercase too, and the OTX
#: tag "chrome rat" was captured as a malware family named `chrome`. Only the
#: category noun is case-insensitive.
_MALWARE_COLLOCATION_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9._-]{2,30})\s+(?i:" + _MALWARE_CATEGORY + r")s?\b"
)

#: CamelCase family names that carry their own category suffix ("PureRAT").
#: The lowercase run before the suffix is what keeps ordinary all-caps words
#: like "GREAT" out.
_CAMEL_MALWARE_RE = re.compile(r"\b[A-Z][a-z0-9]+(?:RAT|Bot|Loader|Stealer|Locker)\b")

#: Families written in all caps ("PEEP", "SNOWLIGHT") are missed by both
#: patterns above: the collocation pattern yields whatever token precedes the
#: category noun -- on H-0003 the generic "Browser" -- and _CAMEL_MALWARE_RE
#: needs a lowercase run. This scan is deliberately bounded twice over: only
#: inside a sentence that already names a malware category, and only tokens of
#: four characters or more, which excludes the bulk of ordinary acronyms
#: (CVE, DNS, API, RAT) without needing to list them.
#:
#: Measured against 50 live OTX pulses before being added: 11 distinct
#: candidates, of which 7 were real names and 4 were the protocol acronyms
#: denied below.
_ALLCAPS_FAMILY_RE = re.compile(r"\b[A-Z][A-Z0-9]{3,14}\b")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n")
_CATEGORY_NOUN_RE = re.compile(r"\b(?:" + _MALWARE_CATEGORY + r")s?\b", re.IGNORECASE)

#: All-caps tokens that are vocabulary rather than names. Protocols, formats
#: and technique nouns -- the false positives the measurement above found,
#: plus the near neighbours of each.
_ACRONYM_STOPWORDS = frozenset(
    {
        "http",
        "https",
        "html",
        "xhtml",
        "json",
        "yaml",
        "xml",
        "csv",
        "socks",
        "socks4",
        "socks5",
        "hvnc",
        "vnc",
        "smtp",
        "imap",
        "pop3",
        "ldap",
        "ntlm",
        "lsass",
        "dcom",
        "wmic",
        "icmp",
        "dhcp",
        "snmp",
        "tls",
        "ssl",
        "ssh",
        "sftp",
        "webdav",
        "uefi",
        "bios",
        "ntfs",
        "mitre",
        "attck",
        "osint",
        "dfir",
        "cisa",
        "nist",
        "siem",
        "soar",
        "ueba",
        "iocs",
        "ttps",
        "cves",
        "urls",
        "apis",
        "dlls",
        "exes",
        "powershell",
        "cmdline",
        "base64",
        "utf8",
        "ascii",
        "sha256",
        "sha1",
        "md5",
        "aes256",
        "hmac",
        "rsa2048",
        "curl",
        "wget",
        # Our own scaffolding and provider labels, not intelligence. The hunt
        # template's "DRAFT" marker sits in a title line that also names a
        # category ("... Ransomware Variant ..."), so it was reported as an
        # UNSUPPORTED malware name -- a false fabrication alarm on every draft.
        "draft",
        "misp",
        "hunt",
        "lock",
        "todo",
        "note",
        "none",
        "null",
        "true",
        "false",
        "info",
        "warn",
        "error",
        "rss",
    }
)

#: Capitalised words that precede a category noun without naming anything --
#: sentence openers, determiners and the generic subject the hypothesis
#: template uses.
_ENTITY_STOPWORDS = frozenset(
    {
        "the",
        "this",
        "that",
        "these",
        "those",
        "a",
        "an",
        "its",
        "their",
        "his",
        "her",
        "our",
        "your",
        "adversaries",
        "attackers",
        "actors",
        "threat",
        "malicious",
        "known",
        "new",
        "same",
        "such",
        "one",
        "each",
        "any",
        "some",
        "other",
        "another",
        "custom",
        "unknown",
        "suspected",
        "and",
        "or",
        "with",
        "for",
        "via",
        "using",
        "detects",
        "detecting",
        # Generic technology and platform nouns. These are capitalised and do
        # sit before a category noun -- "Browser RAT", "Windows loader" -- but
        # name a platform, not a family. "Browser" was graded an asserted
        # malware name on H-0003.
        "browser",
        "chrome",
        "chromium",
        "edge",
        "firefox",
        "safari",
        "windows",
        "linux",
        "macos",
        "android",
        "ios",
        "office",
        "outlook",
        "extension",
        "banking",
        "mobile",
        "remote",
        "native",
        "persistent",
        "generic",
        "modular",
        "commodity",
        # Languages, runtimes and Microsoft features that sit before a
        # category noun ("JavaScript loader", "IoT botnet"). Found by running
        # the extractor over 50 live OTX pulses, not guessed.
        "javascript",
        "powershell",
        "vbscript",
        "typescript",
        "bitlocker",
        "net",
        "iot",
        "multiple",
        "several",
        "various",
        "python",
        "golang",
        "rust",
        "java",
    }
)


def _is_generic_entity(cleaned: str) -> bool:
    """Reject the shapes that name a technology rather than a family.

    A "-based" token is always a description of implementation, never a name:
    the live corpus produced "Rust-based" from "Rust-based loader".
    """
    lowered = cleaned.lower()
    return lowered in _ENTITY_STOPWORDS or lowered.endswith("-based")


_YAML_BLOCK_RE = re.compile(r"```yaml\n(.*?)```", re.DOTALL)


def _detection_section(rule_body: str) -> str:
    """The `detection:` mapping of a Sigma rule, or "" if it has none.

    Indicator claims are scoped to this rather than the whole rule because
    this is the only part that would actually be run. The surrounding
    metadata legitimately carries hostnames that are not indicators at all:
    `references:` cites the article the hunt came from, so auditing the whole
    block reported the *publisher's* domain -- `unit42.paloaltonetworks.com`,
    `socradar.io` -- as an indicator "asserted by CTI". It is asserted by the
    CTI, because the citation really is in the source; it is simply not an
    indicator, and on a hunt whose real IOCs were dropped it was the only
    indicator row, which made an evidence-free draft look evidenced.

    A fabricated C2 domain still lands in `detection:`, so narrowing here
    costs the fabrication check nothing.
    """
    lines = rule_body.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.rstrip() == "detection:")
    except StopIteration:
        return ""
    collected: list[str] = []
    for line in lines[start + 1 :]:
        # A non-indented, non-blank line is the next top-level Sigma key.
        if line.strip() and not line[:1].isspace():
            break
        collected.append(line)
    return "\n".join(collected)


@dataclass
class TechniqueFact:
    """What the live ATT&CK matrix says about one technique ID.

    Supplied by the caller rather than looked up here: the orchestrator
    already resolves every technique through ``hecate-agent attack lookup`` to derive
    tactics and platforms, and each of those is a subprocess call. Re-running
    them inside the audit would double the cost of a draft to re-learn what
    the caller just found out.
    """

    valid: bool = True
    superseded_by: str = ""
    #: Platforms ATT&CK lists for this technique, already relabelled to the
    #: vocabulary the draft's frontmatter uses. Empty means the caller could
    #: not resolve them, which is not the same as a mismatch.
    platforms: tuple[str, ...] = ()


@dataclass
class GroundingClaim:
    """One checkable assertion and whether the evidence supports it."""

    kind: str  # "technique" | "cve" | "indicator" | "entity"
    value: str
    status: str  # "asserted" | "derived" | "unsupported"
    note: str = ""


@dataclass
class GroundingReport:
    claims: list[GroundingClaim] = field(default_factory=list)

    @property
    def unsupported(self) -> list[GroundingClaim]:
        return [c for c in self.claims if c.status == "unsupported"]

    @property
    def counts(self) -> dict[str, int]:
        counts = {"asserted": 0, "corroborated": 0, "derived": 0, "unsupported": 0}
        for claim in self.claims:
            counts[claim.status] = counts.get(claim.status, 0) + 1
        return counts

    @property
    def is_clean(self) -> bool:
        return not self.unsupported


def _scaffolding(value: str) -> bool:
    lowered = value.lower().strip(".")
    return lowered in _SCAFFOLDING or any(lowered.endswith("." + s) for s in _SCAFFOLDING)


def _named_entities(prose: str) -> list[str]:
    """Pull the checkable named entities out of prose.

    Returns family and actor names only -- the things a source either named
    or did not. Everything else a draft says about an adversary is
    interpretation, which is what a hunt is supposed to contain.
    """
    found: list[str] = []

    def keep(value: str) -> None:
        cleaned = value.strip(".,;:'\"")
        if not cleaned or _is_generic_entity(cleaned):
            return
        if cleaned.lower() not in {f.lower() for f in found}:
            found.append(cleaned)

    for match in _ACTOR_DESIGNATOR_RE.findall(prose):
        keep(match)
    for match in _MALWARE_COLLOCATION_RE.findall(prose):
        keep(match)
    for match in _CAMEL_MALWARE_RE.findall(prose):
        keep(match)

    # All-caps families, scoped to sentences that already name a category.
    for sentence in _SENTENCE_SPLIT_RE.split(prose):
        if not _CATEGORY_NOUN_RE.search(sentence):
            continue
        for token in _ALLCAPS_FAMILY_RE.findall(sentence):
            if token.lower() in _ACRONYM_STOPWORDS:
                continue
            keep(token)
    return found


def _is_path_component(text: str, start: int) -> bool:
    """Whether the domain-shaped token at `start` is part of a filesystem path.

    `/Applications/Safari.app` is a path, not a hostname, but the domain
    pattern matches only `Safari.app` -- the separator sits outside the match,
    so `_looks_like_a_filename` never sees it and the token was reported as a
    fabricated domain on a rule that was matching a process parent.

    Deliberately positional rather than another entry in `_FILE_SUFFIXES`:
    `.app` resolves as a real TLD, and that list omits real TLDs on purpose so
    a fabricated C2 domain cannot hide behind one. Path context discriminates
    without creating that blind spot, and it covers the suffixes the list
    could never include -- `/usr/local/bin/deploy.sh` has the same problem.

    A URL's host is also preceded by a separator, so a scheme immediately
    before it means this really is a hostname.
    """
    if start == 0:
        return False
    if text[start - 1] not in "/\\":
        return False
    before = text[:start]
    # `https://evil.com/x` and the protocol-relative `//evil.com` are URL
    # authorities; the token there is the host, not a path segment.
    return not before.endswith(("://", "//"))


def _looks_like_a_filename(value: str) -> bool:
    if "/" in value or "\\" in value:
        return True
    return value.rsplit(".", 1)[-1].lower() in _FILE_SUFFIXES


def audit_draft(
    *,
    draft_text: str,
    cti_text: str,
    research_text: str = "",
    cti_techniques: list[str] | None = None,
    technique_facts: dict[str, TechniqueFact] | None = None,
    hunt_platforms: list[str] | None = None,
) -> GroundingReport:
    """Classify the draft's checkable claims against the evidence behind it.

    The two corpora are kept apart rather than concatenated. ``cti_text`` is
    primary evidence; ``research_text`` is generated, so a claim it alone
    supports is ``corroborated``, not ``asserted``.

    ``technique_facts`` carries what the live ATT&CK matrix says about each
    technique ID, so an invented one can be called out instead of passing as
    a hypothesis inference.
    """
    primary = cti_text.lower()
    secondary = research_text.lower()
    asserted_techniques = {t.upper() for t in (cti_techniques or [])}
    facts = {k.upper(): v for k, v in (technique_facts or {}).items()}

    def grade(value: str) -> tuple[str, str]:
        """Rank one literal against primary then secondary evidence."""
        lowered = value.lower()
        if lowered in primary:
            return "asserted", "in the source CTI"
        if lowered in secondary:
            return "corroborated", "only in the research document, which is itself generated"
        return "unsupported", "in no source"

    report = GroundingReport()
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, status: str, note: str = "") -> None:
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        report.claims.append(GroundingClaim(kind=kind, value=value, status=status, note=note))

    hunt_platforms = list(hunt_platforms or [])

    # --- ATT&CK techniques ------------------------------------------------
    # A technique the hypothesis reasoned to is legitimate; one the source
    # asserted is stronger. The distinction is what a reviewer needs.
    for technique in _TECHNIQUE_RE.findall(draft_text):
        upper = technique.upper()
        fact = facts.get(upper)

        # An ID the matrix does not know is not an inference -- it is an
        # invention, and it looks exactly like a real mapping in frontmatter.
        # Observed: the Sigma generator proposed "T1047.002", which has never
        # existed.
        if fact is not None and not fact.valid:
            add("technique", upper, "unsupported", "no such technique in the current ATT&CK matrix")
            continue

        note_suffix = ""
        if fact is not None and fact.superseded_by:
            note_suffix = f"; revoked by ATT&CK, superseded by {fact.superseded_by}"

        # A technique that exists but cannot occur on the platform this hunt
        # scopes to is a real mapping in the wrong place, and it reads as
        # evidence. Observed: T1059.003 (Windows Command Shell), a
        # Windows-only technique, attached to a hunt scoped to macOS.
        #
        # Only fires when both sides are known and genuinely disjoint. A
        # technique ATT&CK lists on eight or more platforms carries no scoping
        # signal and is excluded upstream, so it never reaches here with a
        # narrow list to contradict.
        if (
            fact is not None
            and fact.platforms
            and hunt_platforms
            and not (set(fact.platforms) & set(hunt_platforms))
        ):
            add(
                "technique",
                upper,
                "unsupported",
                "ATT&CK lists this technique on {} only, but the hunt scopes to {}".format(
                    ", ".join(fact.platforms),
                    ", ".join(hunt_platforms),
                )
                + note_suffix,
            )
            continue

        if upper in asserted_techniques:
            add("technique", upper, "asserted", "named by the source CTI" + note_suffix)
        elif any(
            a.startswith(upper + ".") or upper.startswith(a + ".") for a in asserted_techniques
        ):
            add(
                "technique",
                upper,
                "asserted",
                "sub/parent of a technique the source named" + note_suffix,
            )
        else:
            add(
                "technique",
                upper,
                "derived",
                "inferred by the hypothesis, not named by the source" + note_suffix,
            )

    # --- CVEs -------------------------------------------------------------
    # No generalisation story exists for a CVE: either a source names it or
    # the model made it up.
    for cve in _CVE_RE.findall(draft_text):
        status, note = grade(cve)
        add("cve", cve.upper(), status, note)

    # --- Named entities in prose ------------------------------------------
    # Rule bodies are excluded: a Sigma selection naming a family is derived
    # from the prose above it, not an independent claim, and auditing both
    # would double-count the same assertion.
    prose = _YAML_BLOCK_RE.sub(" ", draft_text)
    for entity in _named_entities(prose):
        status, note = grade(entity)
        add("entity", entity, status, f"actor/malware name {note}")

    # --- Indicators inside generated rules --------------------------------
    # Scoped to each rule's `detection:` section because that is what would
    # actually be run. Prose legitimately paraphrases, and a rule's own
    # metadata legitimately cites sources -- see _detection_section.
    for block in _YAML_BLOCK_RE.findall(draft_text):
        # A block with no `detection:` key is not a runnable rule. Audit the
        # whole of it rather than skipping it: over-reporting on a malformed
        # rule is the safe error for an audit, and the Sigma validator
        # rejects those before they are ever attached to a hunt.
        detection = _detection_section(block) or block
        for pattern, label in ((_IPV4_RE, "ip"), (_DOMAIN_RE, "domain"), (_HASH_RE, "hash")):
            # finditer, not findall: the filename check needs the character
            # before the match, and a path separator never falls inside it.
            for match in pattern.finditer(detection):
                value = match.group(0)
                if _scaffolding(value):
                    continue
                if label == "domain" and (
                    _looks_like_a_filename(value) or _is_path_component(detection, match.start())
                ):
                    continue
                status, note = grade(value)
                add("indicator", value, status, f"{label} {note}")

    return report


def render_grounding_section(report: GroundingReport) -> str:
    """Render the audit for a human reviewing the draft.

    Leads with the unsupported claims when there are any: a reviewer skimming
    a generated hunt needs the fabrication risk first, not a table they have
    to read to the bottom of.
    """
    if not report.claims:
        return "No checkable claims found in this draft.\n"

    counts = report.counts
    lines: list[str] = []

    if report.unsupported:
        lines.append(
            f"> **{len(report.unsupported)} claim(s) trace to no source.** "
            "Treat these as unverified until you have checked them yourself — "
            "they are specific enough to look like evidence and are not."
        )
        for claim in report.unsupported:
            lines.append(f"> - `{claim.value}` ({claim.kind}) — {claim.note}")
        lines.append("")
    else:
        lines.append("> Every checkable claim in this draft traces back to a source.")
        lines.append("")

    if counts["corroborated"]:
        lines.append(
            f"> {counts['corroborated']} claim(s) rest on the research document alone. "
            "Research is generated, so these are a claim about evidence rather than "
            "evidence \u2014 check them against its cited sources before relying on them."
        )
        lines.append("")

    lines.append(
        f"*{counts['asserted']} asserted by CTI \u00b7 {counts['corroborated']} research-only "
        f"\u00b7 {counts['derived']} inferred \u00b7 {counts['unsupported']} unsupported*"
    )
    lines.append("")
    lines.append("| Claim | Type | Grounding |")
    lines.append("|-------|------|-----------|")
    for claim in report.claims:
        label = {
            "asserted": "asserted by CTI",
            "corroborated": "research only",
            "derived": "inferred",
            "unsupported": "**UNSUPPORTED**",
        }[claim.status]
        lines.append(f"| `{claim.value}` | {claim.kind} | {label} — {claim.note or 'n/a'} |")
    lines.append("")
    return "\n".join(lines)
