"""
PyTrace Composite Exporter and Factory.
"""

from __future__ import annotations

import os
from typing import List, Optional, Union
from pytrace.config import PyTraceConfig, get_config
from pytrace.exporters.base import BaseExporter
from pytrace.exporters.file import FileExporter
from pytrace.exporters.fluentbit import FluentBitExporter
from pytrace.exporters.http import HttpExporter
from pytrace.exporters.stdout import StdoutExporter
from pytrace.models.event import PyTraceEvent


class CompositeExporter(BaseExporter):
    """Dispatches events to multiple exporters concurrently/sequentially."""

    def __init__(self, exporters: Optional[List[BaseExporter]] = None):
        self.exporters: List[BaseExporter] = exporters or []

    def add_exporter(self, exporter: BaseExporter) -> None:
        self.exporters.append(exporter)

    def export(self, event: PyTraceEvent) -> None:
        for exp in self.exporters:
            try:
                exp.export(event)
            except Exception:
                pass

    def flush(self) -> None:
        for exp in self.exporters:
            try:
                exp.flush()
            except Exception:
                pass

    def close(self) -> None:
        for exp in self.exporters:
            try:
                exp.close()
            except Exception:
                pass


def create_exporter_from_config(config: Optional[PyTraceConfig] = None) -> BaseExporter:
    """
    Factory function to build exporter pipeline from PyTraceConfig.
    Supports comma-separated targets like 'file,stdout', 'fluentbit', 'stdout', etc.
    """
    cfg = config or get_config()
    types = [t.strip().lower() for t in cfg.exporter_type.split(",") if t.strip()]

    exporters: List[BaseExporter] = []

    for t in types:
        if t == "file":
            exporters.append(FileExporter(log_dir=cfg.log_dir, filename=cfg.log_file))
        elif t == "stdout":
            exporters.append(StdoutExporter(json_format=True))
        elif t == "console":
            exporters.append(StdoutExporter(json_format=False))
        elif t == "fluentbit":
            exporters.append(FluentBitExporter(host=cfg.fluentbit_host, port=cfg.fluentbit_port))

    if not exporters:
        # Default fallback to stdout
        exporters.append(StdoutExporter(json_format=True))

    if len(exporters) == 1:
        return exporters[0]
    return CompositeExporter(exporters)
