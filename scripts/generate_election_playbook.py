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


def inspect_hunt(workspace: Path, hunt_id: str) -> dict:
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
            raise ValueError(f"{hunt_id}: semantic defect in {file.name}: {problem}")
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
                raise ValueError(f"{hunt_id}: expected native file missing: {native.name}")
            query = native.read_text()
            if "\ndetection:" in query or query.startswith("title:"):
                raise ValueError(
                    f"{hunt_id}: Sigma YAML was written into a native query: {native.name}"
                )
            check = validator.validate(target, query)
            if not check.is_valid:
                raise ValueError(
                    f"{hunt_id}: invalid emitted {native.name}: {check.error_messages}"
                )
            if query.strip() != converted.query.strip():
                raise ValueError(
                    f"{hunt_id}: native query disagrees with its Sigma rule: {native.name}"
                )
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
    args = parser.parse_args()
    w = args.workspace.resolve()
    review = w / "playbooks/elections/reviews" / args.review_date
    manifest_path = review / "final-rerun-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if len(manifest) != 2 or any(
        r["exit_code"] != 0 or r.get("output_edits") != "none" for r in manifest
    ):
        raise ValueError(
            "Both corrected CLI reruns must have completed successfully without output edits"
        )
    hunts = []
    for run in manifest:
        log = (review / run.get("log_file", "corrected-" + run["name"] + "-run.log")).read_text()
        ids = re.findall(r"^Hunt ID:\s*(H-\d+)", log, re.M)
        if len(ids) != 1:
            raise ValueError("Expected one completed hunt ID in " + run["name"])
        facts = inspect_hunt(w, ids[0])
        facts.update(name=run["name"], source_url=run["source_url"])
        hunts.append(facts)
    integration = json.loads((review / "integrations.json").read_text())
    blockers = [r for r in integration["checks"] if r["status"] == "fail"]
    status = Counter(r["status"] for r in integration["checks"])
    metadata = {
        "playbook_id": "PB-0001",
        "title": "Election threat hunting and execution playbook",
        "domain": "elections",
        "status": "draft",
        "created_date": "2026-10-16",
        "updated_date": args.review_date,
        "threat_actors": ["Red Heron"],
        "malware_families": ["SocGholish", "JITTERLY", "SIXZUT"],
        "linked_hunts": [h["hunt_id"] for h in hunts],
        "linked_research": [h["research_id"] for h in hunts if h["research_id"]],
    }
    lines = [
        "---",
        yaml.safe_dump(metadata, sort_keys=False).rstrip(),
        "---",
        "",
        "# Election threat hunting and execution playbook",
        "",
        "This playbook is regenerated from the corrected pipeline outputs listed below. Hunt files and query files are read-only inputs to this build. All hunts remain proposals in planning status; no production election infrastructure was queried or declared compromised.",
        "",
        "## CTI scope and provenance",
        "",
        "| Track | Input and interpretation | Current hunt |",
        "| --- | --- | --- |",
    ]
    for h in hunts:
        description = (
            "SocGholish election benchmark; exercise input with no primary report URL. Documentation-range IPs are not live IOC evidence."
            if h["name"] == "socgholish-exercise"
            else "[Acronis Red Heron report]("
            + h["source_url"]
            + "), reread by the source-evidence stage. The report describes RCE against election-titled Gitea servers; their data exfiltration is unconfirmed. It establishes no compromise in this environment."
        )
        lines.append(f"| {h['name']} | {description} | [{h['hunt_id']}](../../{h['hunt_path']}) |")
    lines += [
        "",
        "The two tracks describe different threat paths. Correlate within the relevant asset scope; shared election relevance does not establish a shared actor. The benchmark domains and addresses must not be treated as confirmed current malicious infrastructure or sent to production blocklists.",
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
        "### Conversion gaps",
        "",
    ]
    gaps = [(h["hunt_id"], g) for h in hunts for g in h["conversion_gaps"]]
    if gaps:
        for hid, gap in gaps:
            reason = re.sub(r"\s+", " ", str(gap["reason"]))[:240].strip()
            lines.append(f"- {hid}, `{gap['rule']}`, `{gap['target']}`: {reason}")
    else:
        lines.append("All six local backends produced files for every retained Sigma rule.")
    lines += [
        "",
        "## Latest analyst gate review",
        "",
        f"See the [latest grounding and promotion-policy recheck](reviews/{args.review_date}/latest-gate-recheck.json) and the [detailed analyst review](reviews/{args.review_date}/election_rerun_review.md). H-0896 passes the current grounding and structure checks, but its policy eligibility does not constitute analyst approval or live detection validation.",
        "",
        "H-0898 passes structure validation but currently has 8 unsupported grounding claims and is ineligible under the promotion policy. Resolve or remove those claims, especially values that may describe operator-side artifacts, then rerun grounding and promotion checks before considering promotion.",
        "",
        "## Integration readiness",
        "",
        f"The recorded checks include {status['pass']} passing results, {status['fail']} failed or restricted results, and {status['not_configured']} unconfigured capabilities. See [the full integration evidence](reviews/{args.review_date}/integrations.json). Counts are checks, not unique products.",
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
        "For the Windows exercise, correlate suspicious email attachments or links with script execution and DNS activity on the same endpoint/user. The deterministic DNS proposal covers exact domains and subdomains. Domain matching is a scoping signal; it does not prove payload execution. Obtain real, independently supported CTI before using this exercise track operationally.",
        "",
        "### 2. Windows script execution",
        "",
        "Review script-host process events with expanded temporary-directory paths, command-line context, parent process, user, and file creation. Require the rule to test any property its title claims. WScript alone does not establish Visual Basic; JavaScript language evidence belongs to T1059.007. Examine the generated rule for the precise behavior it covers and its documented gaps.",
        "",
        "### 3. Persistence",
        "",
        "Correlate scheduled-task creation and on-disk task definitions with script execution. Task queries and deletions must not satisfy a creation proposal merely because the task name matches. For registry persistence, distinguish key creation from value modification and account for legitimate installer/administrator changes. An exercise task name is not evidence of a particular registry value.",
        "",
        "### 4. Gitea and Linux persistence",
        "",
        "For the source-backed track, review the newly generated Linux proposals against Gitea application/HTTP events, service-account process creation, file integrity evidence, and network telemetry. Prioritize the source-supported exploit and persistence behaviors. Distinguish artifacts observed on victim systems from operator tooling, redacted command examples, generic capabilities, and URLs belonging to research publishers.",
        "",
        "### 5. Correlation, triage, and escalation",
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
        "## Reproducibility",
        "",
        f"See [the detailed review](reviews/{args.review_date}/election_rerun_review.md), [the rerun manifest](reviews/{args.review_date}/final-rerun-manifest.json), and [the artifact integrity record](reviews/{args.review_date}/playbook-build.json).",
        "",
        "From Hecate-Runner, regenerate this playbook with:",
        "",
        "```bash",
        f".venv/bin/python scripts/generate_election_playbook.py --review-date {args.review_date}",
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
