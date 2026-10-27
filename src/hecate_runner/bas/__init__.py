"""Breach and Attack Simulation (BAS) & Live Adversary Emulation Package.

Provides connectors to MITRE CALDERA, Stratus Red Team, and mock providers
for automated live purple-teaming validation of Hecate threat hunts.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal

from hecate_runner.bas.base import (
    BASExecutionError,
    BASPlatform,
    BASProvider,
    DetonationRequest,
    DetonationResult,
    DetonationStage,
    DetonationTarget,
    SafetyViolationError,
    normalize_platform,
)
from hecate_runner.bas.caldera import CalderaConnector
from hecate_runner.bas.mock import MockBASProvider
from hecate_runner.bas.stratus import StratusConnector
from hecate_runner.bas.verifier import (
    DetectionVerifier,
    VerificationResult,
    VerificationStatus,
)

if TYPE_CHECKING:
    from hecate_runner.config import Settings

log = logging.getLogger(__name__)

__all__ = [
    "BASExecutionError",
    "BASPlatform",
    "BASProvider",
    "CalderaConnector",
    "DetectionVerifier",
    "DetonationRequest",
    "DetonationResult",
    "DetonationStage",
    "DetonationTarget",
    "MockBASProvider",
    "SafetyViolationError",
    "StratusConnector",
    "VerificationResult",
    "VerificationStatus",
    "get_bas_provider",
    "normalize_platform",
]


def get_bas_provider(
    provider_name: Literal["caldera", "stratus", "mock"] | str,
    settings: Settings | None = None,
    allowed_hosts: list[str] | None = None,
    allowed_accounts: list[str] | None = None,
) -> BASProvider:
    """Factory creating configured BAS provider instances."""
    hosts = allowed_hosts or (settings.bas_allowed_hosts if settings else [])
    accounts = allowed_accounts or (settings.bas_allowed_accounts if settings else [])

    name_lower = provider_name.lower().strip()

    if name_lower == "caldera":
        url = settings.caldera_url if settings else "http://localhost:8888"
        api_key = settings.caldera_api_key if settings else None
        group = settings.caldera_agent_group if settings else "staging"
        timeout = settings.caldera_timeout_sec if settings else 120
        return CalderaConnector(
            base_url=url,
            api_key=api_key,
            agent_group=group,
            timeout_sec=timeout,
            allowed_hosts=hosts,
            allowed_accounts=accounts,
        )

    if name_lower == "stratus":
        bin_path = settings.stratus_binary if settings else "stratus-red-team"
        timeout = settings.stratus_timeout_sec if settings else 300
        return StratusConnector(
            binary_path=bin_path,
            timeout_sec=timeout,
            allowed_hosts=hosts,
            allowed_accounts=accounts,
        )

    if name_lower == "mock":
        return MockBASProvider(allowed_hosts=hosts, allowed_accounts=accounts)

    raise ValueError(
        f"Unknown BAS provider '{provider_name}'. Supported providers: 'caldera', 'stratus', 'mock'."
    )
