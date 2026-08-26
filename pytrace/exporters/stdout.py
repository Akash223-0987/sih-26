"""
PyTrace Stdout Exporter.
Outputs structured JSON or formatted summary to standard output.
"""

from __future__ import annotations

import sys
from typing import Optional
from pytrace.exporters.base import BaseExporter
from pytrace.models.event import PyTraceEvent


class StdoutExporter(BaseExporter):
    """
    Exports events directly to sys.stdout.
    Supports raw JSON format or formatted log line.
    """

    def __init__(self, json_format: bool = True, stream=None):
        self.json_format = json_format
        self.stream = stream or sys.stdout

    def export(self, event: PyTraceEvent) -> None:
        try:
            if self.json_format:
                line = event.to_json()
            else:
                # Pretty console format
                severity = event.event.severity
                msg = event.event.message or ""
                trace_id = event.trace.trace_id if event.trace else "-"
                http_part = ""
                if event.http:
                    http_part = f"[{event.http.method} {event.http.path} -> {event.http.status_code} ({event.duration_ms:.1f}ms)] " if event.duration_ms is not None else f"[{event.http.method} {event.http.path}] "
                line = f"{event.timestamp} [{severity}] [{event.service}] [trace={trace_id}] {http_part}{msg}"
            
            self.stream.write(line + "\n")
            self.stream.flush()
        except Exception as ex:
            sys.stderr.write(f"[pytrace] StdoutExporter error: {ex}\n")

    def flush(self) -> None:
        try:
            self.stream.flush()
        except Exception:
            pass

    def close(self) -> None:
        self.flush()
