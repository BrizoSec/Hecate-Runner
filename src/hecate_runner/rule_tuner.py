"""Conversational Sigma rule tuning engine for Human-in-the-Loop (HITL) SecOps.

Interprets natural language analyst feedback from Slack threads (e.g.
"Exclude svchost.exe from the image path", "Filter out CommandLine containing /update",
"Broaden Image to include pwsh.exe"), mutates the detection rule, re-transpiles
across all 6 SIEM/EDR targets, and records the change.
"""

from __future__ import annotations

import difflib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from hecate_runner.atomic_write import atomic_write_text

log = logging.getLogger(__name__)


CANONICAL_FIELDS: dict[str, str] = {
    "image": "Image",
    "commandline": "CommandLine",
    "user": "User",
    "parentimage": "ParentImage",
    "parentcommandline": "ParentCommandLine",
    "currentdirectory": "CurrentDirectory",
    "originalfilename": "OriginalFileName",
    "targetfilename": "TargetFilename",
    "destinationip": "DestinationIp",
    "destinationhostname": "DestinationHostname",
    "destinationport": "DestinationPort",
    "hashes": "Hashes",
    "scriptblocktext": "ScriptBlockText",
    "eventid": "EventID",
    "provider_name": "Provider_Name",
    "queryname": "QueryName",
}


@dataclass
class RuleTuningResult:
    """Outcome of parsing and applying conversational analyst feedback to a rule."""

    ok: bool
    hunt_id: str
    action_summary: str
    rule_file: Path | None = None
    diff: str = ""
    new_rule_yaml: str = ""
    transpiled_targets: list[str] = field(default_factory=list)
    error: str | None = None


class RuleTuner:
    """Parses analyst feedback instructions and mutates Sigma rule YAML."""

    def __init__(self, workspace: Path):
        self.workspace = workspace

    def _infer_field_and_val(self, instruction: str) -> tuple[str, str, str, str]:
        """Infer (action_type, field_name, modifier, target_value) from instruction text."""
        clean = instruction.strip()
        # Strip potential conversational prefix like "For H-0702, please "
        clean = re.sub(r"(?i)^(?:for\s+H-\d{4}[,:\s]+)?(?:please\s+)?", "", clean).strip()

        match_verb = re.match(
            r"(?i)^(exclude|filter\s+out|ignore|suppress|omit|broaden\s+to|expand\s+to|broaden|expand|include|add)\b\s*(.*)",
            clean,
        )
        if not match_verb:
            return "unknown", "", "", ""

        verb = match_verb.group(1).lower()
        rest = match_verb.group(2).strip()
        action_type = (
            "exclude"
            if any(v in verb for v in ["exclude", "filter", "ignore", "suppress", "omit"])
            else "include"
        )

        if not rest:
            return "unknown", "", "", ""

        tokens = rest.split(None, 1)
        first_token = tokens[0].rstrip(":=")
        field_key = first_token.split("|")[0].lower()

        if field_key in CANONICAL_FIELDS:
            field_name = CANONICAL_FIELDS[field_key]
            modifier = first_token.split("|")[1] if "|" in first_token else ""
            val_part = tokens[1] if len(tokens) > 1 else ""
            val_part = re.sub(r"(?i)^to\s+include\s*", "", val_part)
            if re.search(r"(?i)^containing\s*", val_part):
                modifier = modifier or "contains"
                val_part = re.sub(r"(?i)^containing\s*", "", val_part)
            elif re.search(r"(?i)^endswith\s*", val_part):
                modifier = modifier or "endswith"
                val_part = re.sub(r"(?i)^endswith\s*", "", val_part)
            elif re.search(r"(?i)^equals?\s*", val_part):
                val_part = re.sub(r"(?i)^equals?\s*", "", val_part)
            target_val = val_part.strip(" :=\"'").strip()
        else:
            target_val = rest.strip(" :=\"'").strip()
            if any(
                target_val.lower().endswith(ext)
                for ext in (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".sh")
            ):
                field_name = "Image"
                modifier = "endswith"
            elif any(
                u in target_val.upper()
                for u in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ADMIN")
            ):
                field_name = "User"
                modifier = "contains"
            elif "/" in target_val or "-" in target_val:
                field_name = "CommandLine"
                modifier = "contains"
            else:
                field_name = "CommandLine"
                modifier = "contains"

        if not modifier:
            if field_name == "Image":
                if any(
                    target_val.lower().endswith(ext)
                    for ext in (".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".sh")
                ):
                    modifier = "endswith"
                else:
                    modifier = "contains"
            elif field_name in ("CommandLine", "User"):
                modifier = "contains"

        return action_type, field_name, modifier, target_val

    def tune_rule_yaml(self, original_yaml: str, instruction: str) -> tuple[str, str]:
        """Mutate a Sigma rule YAML based on conversational feedback.

        Returns (updated_yaml, action_summary).
        """
        try:
            rule_dict = yaml.safe_load(original_yaml)
            if not isinstance(rule_dict, dict):
                raise ValueError("Original rule is not a valid YAML mapping")
        except Exception as exc:
            raise ValueError(f"Failed to parse rule YAML: {exc}") from exc

        action_type, field_name, modifier, target_val = self._infer_field_and_val(instruction)

        if action_type == "unknown" or not target_val:
            raise ValueError(
                f"Could not understand tuning instruction: '{instruction}'. "
                "Try instructions like 'Exclude svchost.exe', 'Exclude CommandLine /update', "
                "or 'Add Image pwsh.exe'."
            )

        detection = rule_dict.setdefault("detection", {})
        if not isinstance(detection, dict):
            raise ValueError("Rule 'detection' block is missing or not a mapping")

        full_field_key = f"{field_name}|{modifier}" if modifier else field_name

        if action_type == "exclude":
            # Synthesize an exclusion block name
            base_name = target_val.rsplit(".", 1)[0] if "." in target_val else target_val
            clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", base_name).strip("_").lower()
            if not clean_name:
                clean_name = "exclusion"
            filter_name = f"filter_{clean_name[:20]}"
            counter = 1
            while filter_name in detection:
                filter_name = f"filter_{clean_name[:15]}_{counter}"
                counter += 1

            # Format value (escape windows backslash if endswith executable)
            fmt_val = target_val
            if modifier == "endswith" and not fmt_val.startswith(("\\", "/")):
                fmt_val = f"\\{fmt_val}"

            detection[filter_name] = {full_field_key: fmt_val}

            # Update condition
            curr_cond = str(detection.get("condition", "selection")).strip()
            if "not " in curr_cond:
                new_cond = f"{curr_cond} and not {filter_name}"
            else:
                new_cond = f"({curr_cond}) and not {filter_name}"
            detection["condition"] = new_cond

            summary = f"Added exclusion filter `{filter_name}`: `{full_field_key}: {fmt_val}`"

        else:  # action_type == "include"
            # Find primary selection block
            target_block = None
            for key in ["selection", "selection_main", "selection_1"]:
                if key in detection and isinstance(detection[key], dict):
                    target_block = detection[key]
                    break

            if not target_block:
                for key, val in detection.items():
                    if key not in ("condition", "timeframe") and isinstance(val, dict):
                        target_block = val
                        break

            if not target_block:
                detection["selection_custom"] = {full_field_key: target_val}
                curr_cond = str(detection.get("condition", "selection")).strip()
                detection["condition"] = f"{curr_cond} or selection_custom"
                summary = f"Added new selection block with `{full_field_key}: {target_val}`"
            else:
                # Append or convert to list
                existing_key = None
                for k in target_block:
                    if k.split("|")[0].lower() == field_name.lower():
                        existing_key = k
                        break

                key_to_use = existing_key or full_field_key
                curr_val = target_block.get(key_to_use)
                if curr_val is None:
                    target_block[key_to_use] = target_val
                elif isinstance(curr_val, list):
                    if target_val not in curr_val:
                        curr_val.append(target_val)
                else:
                    if curr_val != target_val:
                        target_block[key_to_use] = [curr_val, target_val]

                summary = f"Expanded `{key_to_use}` with `{target_val}`"

        updated_yaml = yaml.dump(rule_dict, sort_keys=False)
        return updated_yaml, summary

    def tune_hunt_rule(self, hunt_id: str, instruction: str) -> RuleTuningResult:
        """Find the Sigma rule for a hunt, apply tuning instruction, and persist changes."""
        query_dir = self.workspace / "queries" / hunt_id
        if not query_dir.exists():
            return RuleTuningResult(
                ok=False,
                hunt_id=hunt_id,
                action_summary="",
                error=f"Query directory not found for {hunt_id} at {query_dir}",
            )

        sigma_files = sorted(list(query_dir.glob("*.yml")) + list(query_dir.glob("*.yaml")))
        if not sigma_files:
            return RuleTuningResult(
                ok=False,
                hunt_id=hunt_id,
                action_summary="",
                error=f"No Sigma YAML files found under {query_dir}",
            )

        rule_file = sigma_files[0]
        original_yaml = rule_file.read_text(encoding="utf-8")

        try:
            new_yaml, summary = self.tune_rule_yaml(original_yaml, instruction)
        except Exception as exc:
            return RuleTuningResult(
                ok=False,
                hunt_id=hunt_id,
                action_summary="",
                rule_file=rule_file,
                error=str(exc),
            )

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(
                original_yaml.splitlines(keepends=True),
                new_yaml.splitlines(keepends=True),
                fromfile=f"a/{rule_file.name}",
                tofile=f"b/{rule_file.name}",
            )
        )
        diff_text = "".join(diff_lines)

        # Transpile across all targets
        from hecate_agent.api import transpile_sigma_rule

        trans_results = transpile_sigma_rule(new_yaml)
        successful_targets: list[str] = []

        ext_map = {
            "sentinel_kql": ".kql",
            "crowdstrike_cql": ".cql",
            "rapid7_leql": ".leql",
            "sentinelone_s1ql": ".s1ql",
            "splunk_spl": ".spl",
            "elastic_eql": ".eql",
        }

        # Atomically write updated Sigma rule
        atomic_write_text(rule_file, new_yaml)

        # Update transpiled query files
        stem = rule_file.stem
        for tgt, t_res in trans_results.items():
            if getattr(t_res, "success", False) and getattr(t_res, "query", None):
                ext = ext_map.get(tgt)
                if ext:
                    q_path = query_dir / f"{stem}{ext}"
                    atomic_write_text(q_path, t_res.query.strip() + "\n")
                    successful_targets.append(tgt)

        # Also update the hunt markdown file if present
        matches = sorted((self.workspace / "hunts").glob(f"**/{hunt_id}.md"))
        if matches:
            hunt_doc = matches[0]
            try:
                doc_text = hunt_doc.read_text(encoding="utf-8")
                # Append a note in Revision / Grounding history
                tuning_note = (
                    f"\n\n### Conversational Rule Tuning ({instruction})\n"
                    f"- **Summary:** {summary}\n"
                    f"- **Updated Targets:** {', '.join(successful_targets)}\n"
                )
                atomic_write_text(hunt_doc, doc_text + tuning_note)
            except Exception as h_err:
                log.debug("Note update to %s skipped (%s)", hunt_doc.name, h_err)

        log.info("Successfully tuned rule for %s: %s", hunt_id, summary)
        return RuleTuningResult(
            ok=True,
            hunt_id=hunt_id,
            action_summary=summary,
            rule_file=rule_file,
            diff=diff_text,
            new_rule_yaml=new_yaml,
            transpiled_targets=successful_targets,
        )
