"""
PyTrace Base Exporter.
Defines the interface for exporting structured telemetry events.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List
from pytrace.models.event import PyTraceEvent


class BaseExporter(ABC):
    """Abstract base class for all event exporters."""

    @abstractmethod
    def export(self, event: PyTraceEvent) -> None:
        """Export a single telemetry event."""
        pass

    def export_batch(self, events: List[PyTraceEvent]) -> None:
        """Export a list of telemetry events."""
        for event in events:
            self.export(event)

    def flush(self) -> None:
        """Flush any pending buffered events."""
        pass

    def close(self) -> None:
        """Release any open resources or connections."""
        self.flush()
