"""
PyTrace Fluent Bit Direct Exporter.
Sends structured events over TCP socket directly to Fluent Bit's TCP / Forward / HTTP input plugins.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from typing import Optional
from pytrace.exporters.base import BaseExporter
from pytrace.models.event import PyTraceEvent


class FluentBitExporter(BaseExporter):
    """
    Direct TCP socket exporter streaming JSON events to Fluent Bit.
    Includes connection retry and resilient non-blocking socket handling.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 24224, tag: str = "pytrace.app", timeout: float = 2.0):
        self.host = host
        self.port = port
        self.tag = tag
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()

    def _connect(self) -> bool:
        """Establish connection to Fluent Bit service."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            self._sock = sock
            return True
        except Exception:
            self._sock = None
            return False

    def export(self, event: PyTraceEvent) -> None:
        """Send JSON payload over TCP socket."""
        payload = (event.to_json() + "\n").encode("utf-8")
        with self._lock:
            if self._sock is None:
                if not self._connect():
                    # Fallback silently or log warning once
                    return
            try:
                self._sock.sendall(payload)
            except Exception:
                # Connection might have dropped, retry once
                try:
                    if self._sock:
                        self._sock.close()
                except Exception:
                    pass
                self._sock = None
                if self._connect():
                    try:
                        self._sock.sendall(payload)
                    except Exception:
                        self._sock = None

    def close(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
