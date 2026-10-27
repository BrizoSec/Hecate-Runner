"""Adversary Emulation & Breach and Attack Simulation (BAS) Base Layer.

Defines the core data structures, safety constraints, and abstract provider
interfaces for live and simulated adversary emulation across endpoint and
cloud environments.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

log = logging.getLogger(__name__)


class SafetyViolationError(RuntimeError):
    """Raised when an emulation action targets a non-whitelisted host, account, or environment."""


class BASExecutionError(RuntimeError):
    """Raised when an emulation detonation or cleanup fails unexpectedly."""


class DetonationStage(StrEnum):
    """Current operational stage of an adversary emulation procedure."""

    QUEUED = "queued"
    WARMING_UP = "warming_up"
    DETONATING = "detonating"
    CLEANING_UP = "cleaning_up"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class DetonationTarget:
    """Target destination for an adversary emulation detonation."""

    platform: Literal["windows", "linux", "darwin", "aws", "azure", "gcp", "k8s"] = "linux"
    host: str | None = None
    cloud_account: str | None = None
    agent_id: str | None = None
    environment: str = "staging"  # Must never be "production"

    def validate_safety(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
    ) -> None:
        """Enforce strict environment whitelisting prior to running adversary code."""
        if self.environment.lower() in ("production", "prod", "live"):
            raise SafetyViolationError(
                f"Detonation rejected: Environment is flagged as '{self.environment}'. "
                "Adversary emulation can only be executed against staging, lab, or sandbox environments."
            )

        # Host check for endpoint targets
        if (
            self.host
            and allowed_hosts
            and self.host not in allowed_hosts
            and "*" not in allowed_hosts
        ):
            raise SafetyViolationError(
                f"Detonation rejected: Target host '{self.host}' is not in allowed hosts list: {allowed_hosts}"
            )

        # Account check for cloud targets
        if (
            self.cloud_account
            and allowed_accounts
            and self.cloud_account not in allowed_accounts
            and "*" not in allowed_accounts
        ):
            raise SafetyViolationError(
                f"Detonation rejected: Cloud account '{self.cloud_account}' is not in allowed accounts list: {allowed_accounts}"
            )


@dataclass
class DetonationRequest:
    """Parameters requesting execution of an adversary technique."""

    hunt_id: str
    technique_id: str
    ability_id: str | None = None
    platform: Literal["windows", "linux", "darwin", "aws", "azure", "gcp", "k8s"] = "linux"
    target: DetonationTarget = field(default_factory=DetonationTarget)
    timeout_sec: int = 120
    cleanup_on_finish: bool = True
    params: dict[str, Any] = field(default_factory=dict)
    requested_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetonationRequest:
        d = dict(data)
        if "target" in d and isinstance(d["target"], dict):
            d["target"] = DetonationTarget(**d["target"])
        return cls(**d)


@dataclass
class DetonationResult:
    """Outcome of an adversary emulation detonation."""

    success: bool
    hunt_id: str
    technique_id: str
    ability_id: str
    provider: str
    start_time_utc: str
    end_time_utc: str
    duration_seconds: float
    exit_code: int
    stdout: str
    stderr: str
    stage: DetonationStage = DetonationStage.COMPLETED
    cleanup_success: bool = True
    cleanup_error: str | None = None
    telemetry_signatures: list[dict[str, Any]] = field(default_factory=list)
    raw_details: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stage"] = self.stage.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DetonationResult:
        d = dict(data)
        if "stage" in d:
            d["stage"] = DetonationStage(d["stage"])
        return cls(**d)

    def summary(self) -> str:
        status_symbol = "✓" if self.success else "✗"
        return (
            f"[{status_symbol}] {self.provider.upper()}: {self.technique_id} ({self.ability_id}) - "
            f"Exit: {self.exit_code} ({self.duration_seconds:.2f}s) - Cleanup: {'OK' if self.cleanup_success else 'FAILED'}"
        )


class BASProvider(ABC):
    """Abstract Base Class for Breach and Attack Simulation / Adversary Emulation providers."""

    name: str = "base"
    provider_type: str = "generic"

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        allowed_accounts: list[str] | None = None,
    ):
        self.allowed_hosts = allowed_hosts or []
        self.allowed_accounts = allowed_accounts or []

    def check_safety(self, target: DetonationTarget) -> None:
        """Enforce safety whitelist constraints."""
        target.validate_safety(
            allowed_hosts=self.allowed_hosts,
            allowed_accounts=self.allowed_accounts,
        )

    @abstractmethod
    def lookup_technique(self, technique_id: str) -> list[str]:
        """Find supported ability or procedure IDs matching a MITRE ATT&CK technique."""

    @abstractmethod
    def detonate(self, request: DetonationRequest) -> DetonationResult:
        """Trigger live or simulated adversary emulation of the requested ability."""

    @abstractmethod
    def cleanup(self, request: DetonationRequest) -> bool:
        """Execute post-detonation teardown and artifact removal."""

    @abstractmethod
    def health_check(self) -> dict[str, Any]:
        """Verify reachability and operational readiness of the emulation provider."""
