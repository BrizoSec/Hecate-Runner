"""A provider holding one item someone handed over, in place of a feed.

For work that starts from intelligence already in hand: an operator drafting
from text they supply, or a gold case replayed through the pipeline. Intake
is the only thing that differs; the cycle that follows is the one every feed
item goes through.
"""

from __future__ import annotations

from hecate_runner.cti.base import CTIItem, CTIProvider


class SingleItemProvider(CTIProvider):
    """Offers one item until it is acknowledged, then nothing."""

    name = "manual"

    def __init__(self, item: CTIItem) -> None:
        self._item: CTIItem | None = item

    def next_item(self) -> CTIItem | None:
        return self._item

    def acknowledge(self, item: CTIItem) -> None:
        if item is self._item:
            self._item = None
