"""Protect playbook aggregation from the artifact corruption found in the rerun."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from hecate_agent.core.sigma_transpiler import SigmaTranspiler

_spec = spec_from_file_location(
    "election_playbook", Path(__file__).parents[1] / "scripts/generate_election_playbook.py"
)
_module = module_from_spec(_spec)
_spec.loader.exec_module(_module)

RULE = """title: Suspicious script host
id: 85861f08-1d8b-4b89-a38c-44dd4c4a7917
hunt_id: H-0001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\wscript.exe'
  condition: selection
"""


def _workspace(tmp_path, source=RULE):
    hunts = tmp_path / "hunts/2026/Q4"
    hunts.mkdir(parents=True)
    (hunts / "H-0001.md").write_text(
        "---\nhunt_id: H-0001\nplatform: [Windows]\nspawned_from: R-0001\n---\n```yaml\n"
        + source
        + "```\n"
    )
    query_dir = tmp_path / "queries/H-0001"
    query_dir.mkdir(parents=True)
    rule = query_dir / "process_creation__script.yml"
    rule.write_text(source)
    for result in SigmaTranspiler().transpile(source).values():
        assert result.success, result.error_message
        rule.with_suffix(result.file_extension).write_text(result.query + "\n")
    return rule


def test_aggregation_reads_artifacts_without_modifying_them(tmp_path):
    _workspace(tmp_path)
    before = {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    facts = _module.inspect_hunt(tmp_path, "H-0001")
    assert facts["rules"] == 1
    assert len(facts["native_files"]) == 6
    assert before == {str(p): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


def test_aggregation_rejects_a_rule_overwritten_by_another_rule(tmp_path):
    rule = _workspace(tmp_path)
    duplicate = rule.with_name("process_creation__another.yml")
    duplicate.write_text(RULE)
    for native in rule.parent.glob(rule.stem + ".*"):
        if native.suffix != ".yml":
            duplicate.with_suffix(native.suffix).write_bytes(native.read_bytes())
    with pytest.raises(ValueError, match="duplicate Sigma ID"):
        _module.inspect_hunt(tmp_path, "H-0001")


def test_aggregation_rejects_yaml_written_into_a_native_query(tmp_path):
    rule = _workspace(tmp_path)
    rule.with_suffix(".kql").write_text(RULE)
    with pytest.raises(ValueError, match="Sigma YAML was written into a native query"):
        _module.inspect_hunt(tmp_path, "H-0001")


def test_aggregation_rejects_a_valid_query_from_a_different_rule(tmp_path):
    rule = _workspace(tmp_path)
    unrelated = RULE.replace("wscript.exe", "schtasks.exe")
    converted = SigmaTranspiler().transpile(unrelated)["sentinel_kql"]
    assert converted.success
    rule.with_suffix(".kql").write_text(converted.query)
    with pytest.raises(ValueError, match="native query disagrees with its Sigma rule"):
        _module.inspect_hunt(tmp_path, "H-0001")


def test_aggregation_rejects_a_parseable_rule_with_misleading_claims(tmp_path):
    _workspace(tmp_path, "description: Detects obfuscated command-line arguments\n" + RULE)
    with pytest.raises(ValueError, match="semantic defect"):
        _module.inspect_hunt(tmp_path, "H-0001")


def test_aggregation_rejects_a_rule_for_the_wrong_hunt_platform(tmp_path):
    _workspace(tmp_path, RULE.replace("product: windows", "product: linux"))
    with pytest.raises(ValueError, match="rule platform disagrees with hunt scope"):
        _module.inspect_hunt(tmp_path, "H-0001")
