"""Parser protocol.

Every parser takes an ArtifactSource and yields RawEvents. Parsers must not perform
any cross-source correlation — that's the job of the correlation layer.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from ..core.models import RawEvent
from ..sources.base import ArtifactSource


class Parser(Protocol):
    """Extracts RawEvents from a particular kind of artifact."""

    name: str  # short identifier, e.g., "registry_usb"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        """Yield RawEvents from the source. Should not raise on missing artifacts —
        log a warning and return empty instead.
        """
        ...
