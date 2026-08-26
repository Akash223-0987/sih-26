"""
PyTrace HTTP Exporter.
Sends structured events to an HTTP/HTTPS endpoint or collector.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, Optional
from pytrace.exporters.base import BaseExporter
from pytrace.models.event import PyTraceEvent


class HttpExporter(BaseExporter):
    """
    HTTP POST exporter for forwarding events to HTTP log sinks, Fluent Bit HTTP input, or ingestion gateways.
    """

    def __init__(self, endpoint_url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 3.0):
        self.endpoint_url = endpoint_url
        self.headers = {"Content-Type": "application/json"}
        if headers:
            self.headers.update(headers)
        self.timeout = timeout

    def export(self, event: PyTraceEvent) -> None:
        try:
            data = event.to_json().encode("utf-8")
            req = urllib.request.Request(self.endpoint_url, data=data, headers=self.headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                _ = resp.read()
        except Exception:
            # Resilient fail-safe
            pass
