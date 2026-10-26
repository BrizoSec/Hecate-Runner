"""Tests for native EDR query transpilation and publication (Milestone 1)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from hecate_runner.config import Settings
from hecate_runner.github_publisher import _snapshot_bundle
from hecate_runner.hecate_client import HypothesisResult
from hecate_runner.hunt_writer import DraftHuntRequest, write_draft


@pytest.fixture
def sample_request(tmp_path: Path) -> DraftHuntRequest:
    hyp = HypothesisResult(
        hypothesis="Adversaries execute DTHelper.exe to establish persistence.",
        justification="Common persistence technique.",
        techniques=["T1543.003"],
        data_sources=["process_creation"],
        observables=["DTHelper.exe"],
        false_positives=["Legitimate administration"],
        raw_output="raw",
    )
    rule_yaml = """title: Detection of DTHelper.exe Execution
id: 11111111-2222-3333-4444-555555555555
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\DTHelper.exe'
  condition: selection
level: high
"""
    return DraftHuntRequest(
        hunt_id="H-9999",
        threat_intel="Test Hunt with Transpiled Queries",
        hypothesis=hyp,
        sigma_rules=[
            {
                "logsource_category": "process_creation",
                "title": "Detection of DTHelper.exe Execution",
                "level": "high",
                "techniques": ["T1543.003"],
                "rule_yaml": rule_yaml,
            }
        ],
        generated_at=datetime.now(UTC),
        platforms=["Windows"],
        sigma_rule_dir="queries/H-9999",
    )


def test_hunt_writer_renders_native_edr_queries(sample_request: DraftHuntRequest, tmp_path: Path):
    hunts_root = tmp_path / "hunts"
    draft_path = write_draft(sample_request, hunts_root)

    assert draft_path.exists()
    content = draft_path.read_text(encoding="utf-8")

    # Verify native EDR query section is rendered in Markdown
    assert "##### Native EDR & SIEM Queries" in content
    assert "Microsoft Defender / Microsoft Sentinel (KQL):" in content
    assert "DeviceProcessEvents" in content
    assert "CrowdStrike Falcon (LogScale / Raptor) (CQL):" in content
    assert "Rapid7 InsightIDR (LEQL):" in content
    assert "where(process.exe_path=" in content
    assert "SentinelOne (S1QL / Deep Visibility) (S1QL):" in content
    assert "Splunk Enterprise / Cloud (SPL) (SPL):" in content
    assert "Elastic Security (EQL) (EQL):" in content
    assert "process.executable.caseless" in content


def test_github_publisher_allows_edr_query_extensions(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hunts_dir = workspace / "hunts" / "2026" / "Q4"
    hunts_dir.mkdir(parents=True)
    queries_dir = workspace / "queries" / "H-9999"
    queries_dir.mkdir(parents=True)

    # Create valid promotion policy
    policy_yaml = """version: 1
target_visibility: private
auto_merge:
  enabled: true
  merge_method: squash
risk:
  missing_cti: review
  missing_research: review
  missing_sigma: review
  incomplete_metadata: review
  low_confidence_source: review
  unsupported_claims: review
  tlp_amber: review
  unknown_tlp: allow_private
review:
  minimum_approvals: 1
  allowed_associations:
    - OWNER
publisher_login: hecate-publisher[bot]
"""
    (workspace / "promotion-policy.yaml").write_text(policy_yaml, encoding="utf-8")

    # Create hunt draft with frontmatter
    (hunts_dir / "H-9999.md").write_text(
        "---\nhunt_id: H-9999\ntitle: Test Hunt\n---\n# H-9999 Test Hunt", encoding="utf-8"
    )

    # Create canonical YAML and transpiled query files
    (queries_dir / "process__rule.yml").write_text("title: Test Sigma Rule", encoding="utf-8")
    (queries_dir / "process__rule.kql").write_text(
        "DeviceProcessEvents | where FileName == 'test.exe'", encoding="utf-8"
    )
    (queries_dir / "process__rule.cql").write_text(
        "#event_simpleName=ProcessRollup2 ImageFileName=/test\\.exe/", encoding="utf-8"
    )
    (queries_dir / "process__rule.leql").write_text(
        "where(process.name=test.exe)", encoding="utf-8"
    )
    (queries_dir / "process__rule.s1ql").write_text(
        'EventType = "Process Creation"', encoding="utf-8"
    )
    (queries_dir / "process__rule.spl").write_text('Image="*\\test.exe"', encoding="utf-8")
    (queries_dir / "process__rule.eql").write_text(
        'any where process.name == "test.exe"', encoding="utf-8"
    )

    settings = Settings(hecate_workspace=workspace)
    bundle_files, _ = _snapshot_bundle(settings, "H-9999")

    assert "hunts/2026/Q4/H-9999.md" in bundle_files
    assert "queries/H-9999/process__rule.yml" in bundle_files
    assert "queries/H-9999/process__rule.kql" in bundle_files
    assert "queries/H-9999/process__rule.cql" in bundle_files
    assert "queries/H-9999/process__rule.leql" in bundle_files
    assert "queries/H-9999/process__rule.s1ql" in bundle_files
    assert "queries/H-9999/process__rule.spl" in bundle_files
    assert "queries/H-9999/process__rule.eql" in bundle_files


def test_transpiled_query_validation_integration():
    from hecate_agent.api import transpile_sigma_rule, validate_transpiled_query

    rule = """title: Process Execution Test
id: 99999999-0000-1111-2222-333333333333
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\malware.exe'
  condition: selection
"""
    results = transpile_sigma_rule(rule)
    for target, query_res in results.items():
        if query_res.success:
            val = validate_transpiled_query(target, query_res.query)
            assert val["is_valid"] is True
            assert val["sanity_score"] >= 0.8
            assert val["error_messages"] == []


def test_cli_deploy_queries_command(tmp_path: Path):
    from unittest import mock

    from typer.testing import CliRunner

    from hecate_runner.cli import app

    runner = CliRunner()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    queries_dir = workspace / "queries" / "H-9999"
    queries_dir.mkdir(parents=True)
    (queries_dir / "process__rule.spl").write_text('Image="*\\cmd.exe"', encoding="utf-8")
    (queries_dir / "process__rule.kql").write_text(
        "DeviceProcessEvents | where FileName == 'cmd.exe'", encoding="utf-8"
    )

    with mock.patch.dict("os.environ", {"HECATE_WORKSPACE": str(workspace)}):
        result = runner.invoke(app, ["deploy-queries", "H-9999", "--dry-run"])
        assert result.exit_code == 0
        assert "SIEM & EDR Query Deployment for H-9999" in result.output
        assert "splunk_spl" in result.output
        assert "sentinel_kql" in result.output
        assert "dry_run" in result.output
