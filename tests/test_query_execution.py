"""Tests for the propose/execute guardrail logic and providers."""

from __future__ import annotations

from pathlib import Path

import pytest

from sec7669.query_execution import (
    MockQueryProvider,
    ProposedQuery,
    SplunkQueryProvider,
    get_provider,
    validate_guardrails,
)


def _query(**overrides: object) -> ProposedQuery:
    defaults = dict(
        hunt_id="H-0001",
        data_source="splunk",
        query_text="index=main | head 10",
        time_range_days=7,
        limit=100,
    )
    defaults.update(overrides)
    return ProposedQuery(**defaults)  # type: ignore[arg-type]


class TestValidateGuardrails:
    def test_valid_query_has_no_violations(self) -> None:
        assert validate_guardrails(_query()) == []

    def test_empty_query_text_rejected(self) -> None:
        violations = validate_guardrails(_query(query_text="   "))
        assert any("query_text" in v for v in violations)

    def test_time_range_over_max_rejected(self) -> None:
        violations = validate_guardrails(_query(time_range_days=30), max_time_range_days=7)
        assert any("time_range_days" in v for v in violations)

    def test_time_range_at_max_is_allowed(self) -> None:
        assert validate_guardrails(_query(time_range_days=7), max_time_range_days=7) == []

    def test_zero_or_negative_time_range_rejected(self) -> None:
        violations = validate_guardrails(_query(time_range_days=0))
        assert any("time_range_days" in v for v in violations)

    def test_limit_over_max_rejected(self) -> None:
        violations = validate_guardrails(_query(limit=50000), max_limit=1000)
        assert any("limit" in v for v in violations)

    def test_limit_at_max_is_allowed(self) -> None:
        assert validate_guardrails(_query(limit=1000), max_limit=1000) == []

    def test_zero_or_negative_limit_rejected(self) -> None:
        violations = validate_guardrails(_query(limit=0))
        assert any("limit" in v for v in violations)

    def test_missing_data_source_rejected(self) -> None:
        violations = validate_guardrails(_query(data_source=""))
        assert any("data_source" in v for v in violations)

    def test_multiple_violations_all_reported(self) -> None:
        violations = validate_guardrails(_query(time_range_days=999, limit=999999, query_text=""))
        assert len(violations) == 3


class TestProposedQuerySerialization:
    def test_round_trips_through_dict(self) -> None:
        original = _query(justification="testing round trip")
        restored = ProposedQuery.from_dict(original.to_dict())
        assert restored == original

    def test_from_dict_ignores_unknown_keys(self) -> None:
        data = _query().to_dict()
        data["unexpected_future_field"] = "ignored"
        # Must not raise.
        ProposedQuery.from_dict(data)


class TestMockQueryProvider:
    def test_always_succeeds_without_touching_anything(self) -> None:
        provider = MockQueryProvider()
        result = provider.execute(_query())
        assert result.ok
        assert result.provider == "mock"
        assert result.row_count == 0
        assert "Mock provider" in result.detail


class TestGetProvider:
    def test_mock_provider_needs_no_args(self) -> None:
        provider = get_provider("mock")
        assert isinstance(provider, MockQueryProvider)

    def test_splunk_provider_requires_athf_bin_and_workspace(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="requires athf_bin"):
            get_provider("splunk")

    def test_splunk_provider_constructs_with_args(self, tmp_path: Path) -> None:
        provider = get_provider("splunk", athf_bin=tmp_path / "athf", workspace=tmp_path)
        assert isinstance(provider, SplunkQueryProvider)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown query provider"):
            get_provider("bigquery")


class TestSplunkQueryProvider:
    def _make_fake_athf(self, tmp_path: Path, script: str) -> Path:
        fake = tmp_path / "fake_athf.sh"
        fake.write_text(script)
        fake.chmod(0o755)
        return fake

    def test_parses_json_array_after_banner(self, tmp_path: Path) -> None:
        # Mirrors real `athf splunk search --format json` output: a
        # human-readable banner precedes the JSON array even in JSON mode.
        script = (
            "#!/bin/sh\n"
            "printf 'Executing query: index=main\\n'\n"
            "printf 'Time range: -7d to now\\n\\n'\n"
            "printf '[{\"user\": \"alice\"}, {\"user\": \"bob\"}]'\n"
        )
        fake = self._make_fake_athf(tmp_path, script)
        provider = SplunkQueryProvider(athf_bin=fake, workspace=tmp_path)

        result = provider.execute(_query())
        assert result.ok
        assert result.row_count == 2

    def test_nonzero_exit_is_an_error(self, tmp_path: Path) -> None:
        fake = self._make_fake_athf(tmp_path, "#!/bin/sh\necho 'auth failed' >&2\nexit 1\n")
        provider = SplunkQueryProvider(athf_bin=fake, workspace=tmp_path)

        result = provider.execute(_query())
        assert not result.ok
        assert "auth failed" in result.detail

    def test_no_json_array_in_output_is_an_error(self, tmp_path: Path) -> None:
        fake = self._make_fake_athf(tmp_path, "#!/bin/sh\necho 'No results found'\n")
        provider = SplunkQueryProvider(athf_bin=fake, workspace=tmp_path)

        result = provider.execute(_query())
        assert not result.ok

    def test_timeout_is_an_error(self, tmp_path: Path) -> None:
        fake = self._make_fake_athf(tmp_path, "#!/bin/sh\nsleep 5\n")
        provider = SplunkQueryProvider(athf_bin=fake, workspace=tmp_path, timeout_sec=1)

        result = provider.execute(_query())
        assert not result.ok
        assert "timed out" in result.detail

    def test_missing_binary_is_an_error(self, tmp_path: Path) -> None:
        provider = SplunkQueryProvider(athf_bin=tmp_path / "does_not_exist", workspace=tmp_path)

        result = provider.execute(_query())
        assert not result.ok
