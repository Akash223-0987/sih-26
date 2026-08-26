"""
PyTrace Instrumentation Base Module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseInstrumentor(ABC):
    """Abstract interface for framework auto-instrumentors."""

    @abstractmethod
    def instrument(self, app: Any) -> None:
        """Instrument the target application framework instance."""
        pass
