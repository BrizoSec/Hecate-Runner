"""Tests for BAS provider factory and resolution."""

import pytest

from hecate_runner.bas import (
    CalderaConnector,
    MockBASProvider,
    StratusConnector,
    get_bas_provider,
)
from hecate_runner.config import Settings


def test_get_bas_provider_mock():
    provider = get_bas_provider("mock")
    assert isinstance(provider, MockBASProvider)
    assert provider.name == "mock"


def test_get_bas_provider_caldera():
    settings = Settings(
        bas_enabled=True,
        caldera_url="http://caldera-test:8888",
        caldera_api_key="test-key",
        caldera_agent_group="test-group",
        bas_allowed_hosts=["lab-01"],
    )
    provider = get_bas_provider("caldera", settings=settings)
    assert isinstance(provider, CalderaConnector)
    assert provider.base_url == "http://caldera-test:8888"
    assert provider.api_key == "test-key"
    assert provider.agent_group == "test-group"
    assert "lab-01" in provider.allowed_hosts


def test_get_bas_provider_stratus():
    settings = Settings(
        bas_enabled=True,
        stratus_binary="/usr/local/bin/stratus",
        stratus_timeout_sec=180,
        bas_allowed_accounts=["123456789012"],
    )
    provider = get_bas_provider("stratus", settings=settings)
    assert isinstance(provider, StratusConnector)
    assert provider.binary_path == "/usr/local/bin/stratus"
    assert provider.timeout_sec == 180
    assert "123456789012" in provider.allowed_accounts


def test_get_bas_provider_invalid():
    with pytest.raises(ValueError, match="Unknown BAS provider"):
        get_bas_provider("unsupported-provider")


def test_live_factory_rejects_disabled_bas():
    from hecate_runner.bas import SafetyViolationError

    with pytest.raises(SafetyViolationError, match="disabled"):
        get_bas_provider("caldera", settings=Settings(bas_enabled=False))


def test_explicit_empty_allowlist_does_not_inherit_settings():
    provider = get_bas_provider(
        "caldera",
        settings=Settings(bas_enabled=True, bas_allowed_hosts=["lab-01"]),
        allowed_hosts=[],
    )
    assert provider.allowed_hosts == []
