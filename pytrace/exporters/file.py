"""
PyTrace File Exporter.
Appends JSONL events to disk for Fluent Bit collection or local audit.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional
from pytrace.exporters.base import BaseExporter
from pytrace.models.event import PyTraceEvent


class FileExporter(BaseExporter):
    """
    Thread-safe file exporter appending JSON Lines events to target file.
    Tailored for Fluent Bit tail input consumption.
    """

    def __init__(self, filepath: Optional[str] = None, log_dir: Optional[str] = None, filename: str = "application.log"):
        if filepath:
            self.filepath = Path(filepath)
        else:
            base_dir = Path(log_dir or "logs")
            self.filepath = base_dir / filename

        self._lock = threading.Lock()
        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure destination directory exists."""
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def export(self, event: PyTraceEvent) -> None:
        """Serialize event to JSON and append as a line."""
        try:
            line = event.to_json() + "\n"
            with self._lock:
                self._ensure_dir()
                with open(self.filepath, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
        except Exception as ex:
            # Fallback to standard error to prevent crashing application
            import sys
            sys.stderr.write(f"[pytrace] FileExporter error writing to {self.filepath}: {ex}\n")

    def flush(self) -> None:
        """File write flush occurs per write with flush()."""
        pass

    def close(self) -> None:
        pass
