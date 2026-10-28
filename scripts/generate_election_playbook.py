#!/usr/bin/env python3
"""Regenerate PB-0001 from completed CLI reruns without changing hunt artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import yaml
from hecate_agent.core.query_validator import QueryValidator
from hecate_agent.core.sigma_semantics import semantic_problem
from hecate_agent.core.sigma_transpiler import SigmaTranspiler
from sigma.collection import SigmaCollection


def inspect_hunt(workspace: Path, hunt_id: str, *, historical: bool = False) -> dict:
    paths = list((workspace / "hunts").rglob(hunt_id + ".md"))
    if len(paths) != 1:
        raise ValueError(f"{hunt_id}: expected exactly one hunt file")
    path = paths[0]
    text = path.read_text()
    metadata = yaml.safe_load(text.split("---", 2)[1])
    files = sorted((workspace / "queries" / hunt_id).glob("*.y*ml"))
    if not files:
        raise ValueError(f"{hunt_id}: no generated Sigma rules")
    embedded = {}
    for block in re.findall(r"```yaml\n(.*?)\n```", text, re.S):
        doc = yaml.safe_load(block)
        if isinstance(doc, dict) and doc.get("hunt_id") == hunt_id and "detection" in doc:
            embedded[doc["id"]] = doc
    seen = set()
    counts = Counter()
    categories = set()
    issues = []
    hashes = {str(path.relative_to(workspace)): hashlib.sha256(path.read_bytes()).hexdigest()}
    validator = QueryValidator()
    for file in files:
        source = file.read_text()
        SigmaCollection.from_yaml(source)
        rule = yaml.safe_load(source)
        problem = semantic_problem(
            rule["detection"],
            rule["logsource"]["category"],
            f"{rule.get('title', '')}. {rule.get('description', '')}",
        )
        if problem:
            if not historical:
                raise ValueError(f"{hunt_id}: semantic defect in {file.name}: {problem}")
            issues.append({"rule": file.name, "target": "sigma_semantics", "reason": problem})
        scope = metadata.get("platform") or []
        scope = {p.lower() for p in ([scope] if isinstance(scope, str) else scope)}
        product = rule["logsource"].get("product")
        if (
            len(scope) == 1
            and scope <= {"windows", "linux", "macos"}
            and product in {"windows", "linux", "macos"}
            and product not in scope
        ):
            raise ValueError(f"{hunt_id}: rule platform disagrees with hunt scope: {file.name}")
        identity = rule["id"]
        if identity in seen:
            raise ValueError(f"{hunt_id}: duplicate Sigma ID on disk: {identity}")
        seen.add(identity)
        category = rule["logsource"]["category"]
        categories.add(category)
        if not file.name.startswith(category + "__"):
            raise ValueError(f"{hunt_id}: filename/category mismatch: {file.name}")
        if identity not in embedded or any(
            rule.get(k) != embedded[identity].get(k) for k in ("logsource", "detection", "title")
        ):
            raise ValueError(f"{hunt_id}: embedded and on-disk rule disagree: {file.name}")
        hashes[str(file.relative_to(workspace))] = hashlib.sha256(file.read_bytes()).hexdigest()
        for target, converted in SigmaTranspiler().transpile(source).items():
            native = file.with_suffix(converted.file_extension)
            if not converted.success:
                issues.append(
                    {"rule": file.name, "target": target, "reason": converted.error_message}
                )
                continue
            if not native.is_file() or not native.read_text().strip():
                if not historical:
                    raise ValueError(f"{hunt_id}: expected native file missing: {native.name}")
                issues.append(
                    {"rule": file.name, "target": target, "reason": "native query file missing"}
                )
                continue
            query = native.read_text()
            if "\ndetection:" in query or query.startswith("title:"):
                if not historical:
                    raise ValueError(
                        f"{hunt_id}: Sigma YAML was written into a native query: {native.name}"
                    )
                issues.append(
                    {
                        "rule": file.name,
                        "target": target,
                        "reason": "native file contains Sigma YAML rather than a native query",
                    }
                )
                continue
            check = validator.validate(target, query)
            if not check.is_valid:
                if not historical:
                    raise ValueError(
                        f"{hunt_id}: invalid emitted {native.name}: {check.error_messages}"
                    )
                issues.append(
                    {
                        "rule": file.name,
                        "target": target,
                        "reason": "native query validation failed: "
                        + "; ".join(check.error_messages),
                    }
                )
                continue
            if query.strip() != converted.query.strip():
                if not historical:
                    raise ValueError(
                        f"{hunt_id}: native query disagrees with its Sigma rule: {native.name}"
                    )
                issues.append(
                    {
                        "rule": file.name,
                        "target": target,
                        "reason": "native query differs from current Sigma transpilation",
                    }
                )
                continue
            hashes[str(native.relative_to(workspace))] = hashlib.sha256(
                native.read_bytes()
            ).hexdigest()
            counts[target] += 1
    if seen != set(embedded):
        raise ValueError(f"{hunt_id}: rule IDs in the hunt and query directory do not match")
    return {
        "hunt_id": hunt_id,
        "hunt_path": str(path.relative_to(workspace)),
        "research_id": metadata.get("spawned_from"),
        "platforms": metadata.get("platform"),
        "status": metadata.get("status"),
        "title": metadata.get("title"),
        "categories": sorted(categories),
        "rules": len(files),
        "native_files": dict(counts),
        "conversion_gaps": issues,
        "sha256": hashes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace", type=Path, default=Path(__file__).resolve().parents[2] / "Hecate-Workspace"
    )
    parser.add_argument("--review-date", default="2026-10-27")
    parser.add_argument("--manifest-name", default="final-rerun-manifest.json")
    parser.add_argument(
        "--additional-hunt-ids",
        default="",
        help="Comma-separated historical hunt IDs to include in the catalog",
    )
    args = parser.parse_args()
    w = args.workspace.resolve()
    review = w / "playbooks/elections/reviews" / args.review_date
    manifest_path = review / args.manifest_name
    manifest = json.loads(manifest_path.read_text())
    if not manifest or any(
        r["exit_code"] != 0 or r.get("output_edits") != "none" for r in manifest
    ):
        raise ValueError(
            "Every recorded CLI run must have completed successfully without output edits"
        )
    hunts = []
    for run in manifest:
        log = (review / run.get("log_file", "corrected-" + run["name"] + "-run.log")).read_text()
        ids = re.findall(r"^Hunt ID:\s*(H-\d+)", log, re.M)
        if len(ids) != 1:
            raise ValueError("Expected one completed hunt ID in " + run["name"])
        facts = inspect_hunt(w, ids[0])
        facts.update(
            name=run["name"],
            source_url=run.get("source_url"),
            generation=run.get("generation", "recorded rerun"),
        )
        hunts.append(facts)
    additional_ids = [
        value.strip() for value in args.additional_hunt_ids.split(",") if value.strip()
    ]
    for hunt_id in additional_ids:
        if hunt_id in {h["hunt_id"] for h in hunts}:
            continue
        facts = inspect_hunt(w, hunt_id, historical=True)
        facts.update(
            name=hunt_id,
            source_url=None,
            generation="historical original catalog",
        )
        hunts.append(facts)
    integration = json.loads((review / "integrations.json").read_text())
    gate_path = review / "latest-gate-recheck.json"
    gate_data = json.loads(gate_path.read_text())
    gate_rows = {row["hunt_id"]: row for row in gate_data["checks"]}
    missing_gates = [h["hunt_id"] for h in hunts if h["hunt_id"] not in gate_rows]
    if missing_gates:
        raise ValueError("Missing grounding/promotion recheck for: " + ", ".join(missing_gates))
    blockers = [r for r in integration["checks"] if r["status"] == "fail"]
    status = Counter(r["status"] for r in integration["checks"])
    metadata = {
        "playbook_id": "PB-0001",
        "title": "Election-Themed Threat Hunting: Analysis, Research Artifacts, and Multi-Pronged Execution Playbook",
        "domain": "elections",
        "status": "draft",
        "created_date": "2026-10-16",
        "updated_date": args.review_date,
        "threat_actors": ["TA569", "UNC2165", "Red Heron"],
        "malware_families": ["SocGholish", "JITTERLY", "SIXZUT"],
        "mitre_tactics": [
            "Initial Access",
            "Execution",
            "Persistence",
            "Defense Evasion",
            "Command and Control",
            "Lateral Movement",
        ],
        "mitre_techniques": [
            "T1566.001",
            "T1059.007",
            "T1053.005",
            "T1112",
            "T1027.006",
            "T1105",
            "T1190",
            "T1059.004",
            "T1574.006",
        ],
        "linked_hunts": [h["hunt_id"] for h in hunts],
        "linked_research": [h["research_id"] for h in hunts if h["research_id"]],
    }
    lines = [
        "---",
        yaml.safe_dump(metadata, sort_keys=False).rstrip(),
        "---",
        "",
        "# Election-Themed Threat Hunting: Analysis, Research Artifacts, and Multi-Pronged Execution Playbook",
        "",
        "This playbook is regenerated from the corrected pipeline outputs listed below. Hunt files and query files are read-only inputs to this build. All hunts remain proposals in planning status; no production election infrastructure was queried or declared compromised.",
        "",
        "## CTI scope and provenance",
        "",
        "| Track | Input and interpretation | Hunt |",
        "| --- | --- | --- |",
    ]
    for h in hunts:
        current = h["hunt_id"] in {"H-0900", "H-0901"}
        red_heron_ids = {"H-0681", "H-0898", "H-0901"}
        track = (
            "Red Heron / Linux and Gitea"
            if h["hunt_id"] in red_heron_ids
            else "SocGholish / Windows exercise"
        )
        lineage = "Current regeneration" if current else h["generation"]
        if h["hunt_id"] in {"H-0896", "H-0898"}:
            lineage = "Previous PB-0001 version"
        if h["source_url"]:
            description = f"[{lineage}] [Acronis source report]({h['source_url']}); report evidence is not evidence of compromise here."
        elif track.startswith("SocGholish"):
            description = (
                f"{lineage}; exercise/benchmark material, not current malicious IOC evidence."
            )
        else:
            description = f"{lineage}; historical Linux hunt, not a current incident finding."
        lines.append(
            f"| {track} — {h['hunt_id']} | {description} | [{h['hunt_id']}](../../{h['hunt_path']}) |"
        )
    lines += [
        "",
        "These are two distinct threat paths, not evidence of one coordinated campaign. The Red Heron report describes election-tagged target material and Gitea/Linux activity; it does not establish compromise of election systems in this workspace. The SocGholish items are exercise and research drafts. Correlate activity only when local telemetry supports it.",
        "",
        "## Executive summary and threat vectors",
        "",
        "PB-0001 brings together a Windows client-side exercise and a Linux developer-infrastructure threat track. The 13 hunts from the original playbook are retained as historical iterations; H-0896 and H-0898 are the two hunts linked by the immediately preceding playbook; H-0900 and H-0901 are the latest regenerated outputs. A linked hunt is a proposal, not confirmation that the behavior occurred in an election environment.",
        "",
        "| Threat path | Hunting focus | Scope caution |",
        "| --- | --- | --- |",
        "| SocGholish / Windows exercise | Script-host activity, DNS, file and registry persistence, scheduled-task creation | Benchmark domains and RFC 5737 documentation addresses must not be treated as live threat indicators. Validate any operational indicator independently. |",
        "| Red Heron / Gitea and Linux | Gitea web activity, Linux process and file behavior, `/etc/ld.so.preload` changes | Distinguish victim-side evidence from operator tools, redacted examples, publisher URLs, and unverified indicators. The report does not prove local compromise. |",
        "",
        "```mermaid",
        "flowchart LR",
        "  A[Windows exercise: delivery and DNS] --> B[Script host and endpoint behavior]",
        "  B --> C[Task and registry persistence]",
        "  D[Gitea web activity] --> E[Linux process and file behavior]",
        "  C --> F[Correlate against authorized election asset inventory]",
        "  E --> F",
        "```",
        "",
        "The two paths should be investigated independently first. Join them only when host, identity, and time evidence supports a relationship.",
        "",
        "### Research artifacts",
        "",
        "Research is supporting context, not independent proof of claims in a hunt. The linked records span the original SocGholish research series (`R-0648`, `R-0660`, `R-0661`, `R-0684`, `R-0685`, `R-0851`, `R-0853` to `R-0858`), Red Heron research (`R-0705`), and later reruns (`R-0961`, `R-0962`, `R-0964`, `R-0965`). The actor names TA569 and UNC2165 are carried forward from the original source-attribution context; they are not attribution findings about this workspace or an election environment.",
        "",
        "- **SocGholish series:** R-0648 records baseline tradecraft context; R-0660 and R-0661 collect telemetry mapping; R-0684 and R-0685 were used for earlier election-themed iterations; R-0851 and R-0853 to R-0858 document later pipeline and detection iterations. Their assertions still need to be checked against each hunt's cited evidence and the current environment.",
        "- **Red Heron series:** R-0705 and the later R-0962/R-0965 research cover reported Gitea and Linux activity. Treat generated research as search context. Confirm behavior in the linked primary source before attributing an artifact or indicator to a victim.",
        "",
        "## Hunt catalog and lineage",
        "",
        "The original playbook's 13 entries, the two hunts from its immediately previous edition, and both new regenerations are all listed below. Older iterations support historical comparison; use H-0900 and H-0901 as the latest regenerated proposals, subject to the analyst gates and conversion gaps recorded here.",
        "",
        "| Hunt | Research | Lineage | Platform | Log categories | Sigma rules | Native outputs (KQL / EQL / LEQL / SPL / CQL / S1QL) |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for h in hunts:
        lineage = h["generation"]
        if h["hunt_id"] in {"H-0896", "H-0898"}:
            lineage = "Previous playbook"
        elif h["hunt_id"] in {"H-0900", "H-0901"}:
            lineage = "Latest regeneration"
        platforms = ", ".join(h.get("platforms") or []) or "unspecified"
        categories = ", ".join(h.get("categories") or []) or "unspecified"
        counts = [
            str(h["native_files"].get(t, 0))
            for t in [
                "sentinel_kql",
                "elastic_eql",
                "rapid7_leql",
                "splunk_spl",
                "crowdstrike_cql",
                "sentinelone_s1ql",
            ]
        ]
        lines.append(
            f"| [{h['hunt_id']}](../../{h['hunt_path']}) | {h.get('research_id') or '—'} | {lineage} | {platforms} | {categories} | {h['rules']} | {' / '.join(counts)} |"
        )
    lines += [
        "",
        "Original benchmark scores are historical fixture comparisons, not measurements of current detection coverage. Native output counts are existing artifacts that passed this build's local lint; zero means no validated native output was available for that backend/rule. Historical semantic defects and conversion gaps are summarized below; see the build manifest for per-rule details.",
        "",
        "## Query output inventory",
        "",
        "| Hunt | Sigma | KQL | EQL | InsightIDR LEQL | Splunk SPL | CrowdStrike CQL | SentinelOne S1QL |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    targets = [
        "sentinel_kql",
        "elastic_eql",
        "rapid7_leql",
        "splunk_spl",
        "crowdstrike_cql",
        "sentinelone_s1ql",
    ]
    for h in hunts:
        lines.append(
            "| "
            + " | ".join(
                [
                    h["hunt_id"],
                    str(h["rules"]),
                    *[str(h["native_files"].get(t, 0)) for t in targets],
                ]
            )
            + " |"
        )
    lines += [
        "",
        "Native files are stored alongside Sigma in `queries/<hunt-id>/`, using `.kql`, `.eql`, `.leql`, `.spl`, `.cql`, and `.s1ql`. The build checks Sigma parsing, unique IDs, agreement with embedded rules, expected files, and local query lint. These checks do not substitute for a vendor parser, deployed field mappings, or live detection validation.",
        "",
        "KQL endpoint rules use Defender tables where supported. DNS KQL uses Microsoft Sentinel ASIM `_Im_Dns` and `DnsQuery`; the ASIM parser and DNS collection must exist in the target workspace. Rapid7 LEQL uses case-insensitive regular-expression predicates to preserve Sigma wildcard and path semantics. Rapid7 field mappings must match the selected log sets.",
        "",
        "### Artifact and conversion gaps",
        "",
    ]
    detailed_ids = {"H-0896", "H-0898", "H-0900", "H-0901"}
    gaps = [(h["hunt_id"], g) for h in hunts for g in h["conversion_gaps"]]
    if not gaps:
        lines.append("All six local backends produced files for every retained Sigma rule.")
    else:
        for hunt in hunts:
            hunt_gaps = hunt["conversion_gaps"]
            if not hunt_gaps:
                continue
            hid = hunt["hunt_id"]
            if hid in detailed_ids:
                for gap in hunt_gaps:
                    reason = re.sub(r"\s+", " ", str(gap["reason"]))[:240].strip()
                    lines.append(f"- {hid}, `{gap['rule']}`, `{gap['target']}`: {reason}")
            else:
                by_target = Counter(gap["target"] for gap in hunt_gaps)
                summary = ", ".join(
                    f"{target}: {count}" for target, count in sorted(by_target.items())
                )
                lines.append(
                    f"- {hid} (historical): {len(hunt_gaps)} unavailable, invalid, or outdated native output(s) ({summary}); see the per-rule build record."
                )
    lines += [
        "",
        "## Latest analyst gate review",
        "",
        f"See the [latest grounding and promotion-policy recheck](reviews/{args.review_date}/latest-gate-recheck.json) and the [detailed analyst review](reviews/{args.review_date}/election_rerun_review.md). Unsupported claims remain visible in the hunts. Policy requires qualified human review before any review-classified hunt is promoted; those hunts must not auto-merge. A historical planning hunt already on main is not thereby approved for operational use.",
        "",
    ]
    for h in hunts:
        row = gate_rows[h["hunt_id"]]
        grounding = row["grounding"]
        policy = row["promotion_policy"]
        if grounding["unsupported"] or policy["review_required"]:
            values = ", ".join("`" + str(v) + "`" for v in grounding.get("unsupported_values", []))
            suffix = f" Unsupported values: {values}." if values else ""
            lines.append(
                f"- **{h['hunt_id']}: review required before promotion.** "
                f"Grounding: {grounding['cti_asserted']} source-asserted, "
                f"{grounding['inferred']} inferred, {grounding['unsupported']} unsupported; "
                f"promotion eligible: {str(policy['eligible']).lower()}; "
                f"review required: {str(policy['review_required']).lower()}." + suffix
            )
        else:
            lines.append(
                f"- **{h['hunt_id']}: no unsupported claims were reported** in the recorded grounding check. "
                f"Hunt status: `{h['status']}`; "
                f"Promotion eligible: {str(policy['eligible']).lower()}; review required: "
                f"{str(policy['review_required']).lower()}. Eligibility alone is not analyst approval or live detection validation."
            )
    lines += [
        "",
        "## Integration readiness",
        "",
        f"The recorded integration checks (last run {integration.get('checked_at', 'date not recorded')}) include {status['pass']} passing results, {status['fail']} failed or restricted results, and {status['not_configured']} unconfigured capabilities. See [the full integration evidence](reviews/{args.review_date}/integrations.json). Counts are checks, not unique products; this probe was not rerun for the playbook refresh.",
        "",
    ]
    for row in blockers:
        lines.append(
            f"- **{row['integration']}:** {row.get('detail') or 'HTTP ' + str(row.get('http_status', 'failure'))}."
        )
    lines += [
        "",
        "Live SIEM execution is configured as `mock`; vendor deployment is disabled. KQL, EQL, and LEQL generation works independently of an authenticated vendor connection. Slack authentication/channel discovery and GitHub App repository reads were tested; message delivery and PR publication were not exercised. MISP authenticated reads work with local TLS verification disabled. Private OpenCTI, Shadowserver, ANY.RUN APIs and cloud BAS were not established by these checks.",
        "",
        "## Execution prerequisites",
        "",
        "1. Confirm actual election-related assets, ownership, telemetry retention, and collection in [the environment profile](../../knowledge/environment.md). No production sensor coverage is verified in this workspace.",
        "2. Select the appropriate backend and map the generated fields to actual log sources. Verify DNS parser availability, process and registry event types, and Linux audit/file integrity coverage.",
        "3. Use a bounded time range and count-first searches. A zero count without verified sensor coverage is inconclusive. Preserve the exact query, time bounds, timezone, data-source health, and raw result count.",
        "4. Review each proposal and any conversion gap before deployment. Do not substitute synthetic replay or a gold score for live telemetry evidence.",
        "",
        "## Coordinated hunt workflow",
        "",
        "### 1. Delivery and DNS context",
        "",
        "**Objective:** Find a possible delivery-to-execution chain on an authorized Windows asset. Start with email/web events, then join DNS, browser or script-host activity by host, user, and time. Review the current DNS rules in `queries/H-0900/`; older comparison rules are in `queries/H-0796/` and the other cataloged hunts. The deterministic DNS proposal covers values in the exercise input. Domain matching is a scoping signal and does not prove payload execution. RFC 5737 addresses and exercise domains are not live threat indicators.",
        "",
        "**Triage:** Check whether the hostname belongs to the approved election asset inventory, whether the request came from a browser or mail workflow, and whether a file or process event followed. Preserve the source record and time bounds. Do not block an indicator until an analyst confirms its source, role, and current relevance.",
        "",
        "### 2. Windows script execution",
        "",
        "**Objective:** Identify a suspicious script host or related file activity on the same endpoint. Review process creation, parent process, command line, user, image path, and nearby file writes. Compare H-0900's current rules with historical H-0796 rules in `queries/`. Require each rule to test the behavior its title claims. WScript alone does not establish Visual Basic; JavaScript language evidence belongs to T1059.007.",
        "",
        "**Triage:** Check whether the script or archive was downloaded, which process created it, whether it ran, and whether a task or registry change followed. A temporary-directory path by itself is not malicious. Document expected software updates and administrative activity as benign comparisons.",
        "",
        "### 3. Persistence",
        "",
        "**Objective:** Detect persistence changes that follow suspicious execution. Correlate scheduled-task process creation with task-file creation and registry value changes. H-0900's rules are in `queries/H-0900/`; prior task and registry iterations remain in the historical hunt folders.",
        "",
        "**Triage:** Distinguish task creation from query, update, or deletion events. Distinguish registry-key creation from value modification. Inspect the exact task action, executable path, user, and parent process. An exercise task name is not proof that a specific registry value was changed; account for approved software deployment and administrator activity.",
        "",
        "### 4. Gitea and Linux persistence",
        "",
        "**Objective:** Check self-hosted Gitea and Linux telemetry for behaviors described by the source report. Begin with application/web requests and account changes, then correlate service-account processes, file integrity, and outbound network events. H-0901's current rules are in `queries/H-0901/`; H-0898 and H-0681 are historical comparisons. Prioritize source-supported Gitea and `/etc/ld.so.preload` behaviors.",
        "",
        "**Triage:** Establish whether each file or command was observed on a victim system or appears only as operator tooling, a redacted example, a generic capability, or a publisher URL. H-0681 and H-0898 contain unsupported IP/domain claims; do not use those values as blocklist indicators. Retain the claims in those hunts and require qualified analyst review before future promotion or operational use.",
        "",
        "### 5. Election asset and service correlation",
        "",
        "Start from an owner-approved inventory of voter-registration, pollbook, election reporting, campaign, and shared identity services. These hunts do not prove those assets are present or monitored. Correlate a signal to an election asset only after matching its hostname/account to that inventory. Escalate unusual authentication, repository access, or service-account behavior with the asset owner; do not infer voter-data access from a generic server alert.",
        "",
        "### 6. Correlation, triage, and escalation",
        "",
        "Correlate related signals by asset, user/service account, and time. Check expected maintenance, repository administration, and software installation before escalation. Record evidence supporting or falsifying the hypothesis. Escalate confirmed suspicious activity to incident response with host/process timelines and retained artifacts; coordinate containment with asset owners.",
        "",
        "## Validation and decision recording",
        "",
        "Use source-backed positive events and meaningful benign near misses. Record which behaviors were replayed, which had no events, and which failed to match. Synthetic Atomic Red Team telemetry is not execution of an attack on a host. The isolated Linux CALDERA identity smoke test proves only that specific harmless procedure; it does not validate Windows, cloud, or these election detections.",
        "",
        "The historical SocGholish gold set expects documentation-range IPs. Its score measures agreement with that fixture, and can fall when unsafe example IOC rules are correctly rejected. Record failed checks and extra/unreviewed techniques; do not describe 100% fixture agreement as complete detection coverage.",
        "",
        "For each operational run, record the selected hunt/query versions, assets, time window, data-source availability, query counts, synthetic versus live validation, reviewer decision, remaining blind spots, and next action. Keep a hunt in planning while required telemetry or review is missing.",
        "",
        "## Artifact reference guide",
        "",
        "- **Original SocGholish iterations:** H-0644, H-0653, H-0654, H-0669, H-0670, H-0789, and H-0791 through H-0796. H-0670, H-0795, and H-0796 were historically compared with the gold fixture; fixture agreement is not production coverage.",
        "- **Original Red Heron hunt:** H-0681. Its unsupported indicators are listed in the analyst gate review and must not be treated as confirmed IOCs.",
        "- **Previous PB-0001-linked hunts:** H-0896 and H-0898. H-0898 retains unsupported claims and requires analyst review before any future promotion or operational use.",
        "- **Latest regenerated outputs:** H-0900 and H-0901. The run manifest and logs record their inputs, outputs, and hashes.",
        "- **Benchmark fixture:** [SocGholish election targeting](https://github.com/BrizoSec/Hecate-Core/blob/main/evals/gold/socgholish-election-targeting.yaml). It checks agreement with a scenario fixture; do not report its score as detection coverage.",
        "",
        "## Reproducibility",
        "",
        f"See [the detailed review](reviews/{args.review_date}/election_rerun_review.md), [the rerun manifest](reviews/{args.review_date}/{args.manifest_name}), and [the artifact integrity record](reviews/{args.review_date}/playbook-build.json).",
        "",
        "From Hecate-Runner, regenerate this playbook with:",
        "",
        "```bash",
        f".venv/bin/python scripts/generate_election_playbook.py --review-date {args.review_date} --manifest-name {args.manifest_name} --additional-hunt-ids {','.join(additional_ids)}",
        "```",
        "",
    ]
    output = w / "playbooks/elections/election_hunts_and_execution_playbook.md"
    output.write_text("\n".join(lines))
    index = w / "playbooks/README.md"
    if index.exists():
        row = (
            "| **PB-0001** | Elections | [Election Threat Hunting Playbook](elections/election_hunts_and_execution_playbook.md) | SocGholish exercise; Red Heron / JITTERLY / SIXZUT | "
            + ", ".join("`" + h["hunt_id"] + "`" for h in hunts)
            + " | `draft` |"
        )
        index.write_text(re.sub(r"^\| \*\*PB-0001\*\* \|.*$", row, index.read_text(), flags=re.M))
    build = {
        "generated_at": datetime.now(UTC).isoformat(),
        "hunts": hunts,
        "integration_status": dict(status),
        "hunt_output_edits": "none",
        "playbook_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
    }
    (review / "playbook-build.json").write_text(json.dumps(build, indent=2))
    print("Generated", output)
    print(
        json.dumps(
            [
                {"hunt_id": h["hunt_id"], "rules": h["rules"], "native_files": h["native_files"]}
                for h in hunts
            ],
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
