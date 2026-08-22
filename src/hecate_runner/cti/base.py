"""CTI provider abstraction.

Every provider yields a stream of ``CTIItem`` instances that the orchestrator
turns into hunt drafts. Implementations today: file queue, AlienVault OTX,
RSS/Atom feeds. MISP is still open — no live MISP instance to build and
validate against yet.
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
    # Clean, single-field title/link, kept separate from `content` (which is
    # a multi-line blurb assembled for the LLM prompt: title + source +
    # tags + summary + link). Deriving a research topic or a "CTI Sources &
    # References" line by truncating that whole blob is what produced
    # mangled topics ("...Deliver Akira Source:") and search queries
    # contaminated by scaffolding words ("Source:", "Summary:") or, worse,
    # by literal terms from the headline itself (e.g. a title containing
    # "Bing Search" as a phrase, not a topic, sending the web-search agent
    # off after Bing product docs). Providers that have a real title/link
    # populate these directly instead of making callers parse `content`.
    title: str = ""
    source_url: str = ""


class CTIProvider(ABC):
    """Abstract source of CTI. Providers should be stateless where possible."""

    name: str = "abstract"

    @abstractmethod
    def next_item(self) -> CTIItem | None:
        """Return the next CTI item, or None if none is available."""

    @abstractmethod
    def acknowledge(self, item: CTIItem) -> None:
        """Called after successful processing so provider can advance state."""
