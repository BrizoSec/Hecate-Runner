"""CTI provider abstraction.

Every provider yields a stream of ``CTIItem`` instances that the orchestrator
turns into hunt drafts. The file-queue provider is the only implementation
today; OTX/MISP/RSS come later.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class CTIItem:
    """A single CTI blurb that becomes one hunt draft."""

    content: str
    source: str = "unknown"
    received_at: datetime | None = None
    identifier: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class CTIProvider(ABC):
    """Abstract source of CTI. Providers should be stateless where possible."""

    name: str = "abstract"

    @abstractmethod
    def next_item(self) -> CTIItem | None:
        """Return the next CTI item, or None if none is available."""

    @abstractmethod
    def acknowledge(self, item: CTIItem) -> None:
        """Called after successful processing so provider can advance state."""
