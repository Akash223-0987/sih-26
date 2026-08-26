"""
PyTrace Structured Event Models.
Defines the canonical, lossless schema for all telemetry events emitted by pytrace.
"""

from __future__ import annotations

import json
import os
import socket
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format with microsecond precision."""
    return datetime.now(timezone.utc).isoformat()


def get_default_metadata() -> Dict[str, Any]:
    """Capture host, process, thread, and SDK environment metadata."""
    return {
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "thread_id": threading.get_ident(),
        "thread_name": threading.current_thread().name,
        "sdk_name": "pytrace",
        "sdk_version": "0.1.0",
    }


class EventDetails(BaseModel):
    """Event metadata including type, action, severity, and human-readable message."""
    type: str = Field(default="log", description="Event category: http_request, log, exception, metric, span, custom")
    action: Optional[str] = Field(default=None, description="Specific action: initiated, completed, failed, processed")
    severity: str = Field(default="INFO", description="Log level or severity: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    message: Optional[str] = Field(default=None, description="Human readable description or log message")


class HttpDetails(BaseModel):
    """Details for HTTP transactions."""
    method: Optional[str] = Field(default=None, description="HTTP verb: GET, POST, PUT, DELETE, etc.")
    path: Optional[str] = Field(default=None, description="Request path, e.g. /api/users/123")
    route: Optional[str] = Field(default=None, description="Route pattern, e.g. /api/users/{user_id}")
    status_code: Optional[int] = Field(default=None, description="HTTP response status code")
    client_ip: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="User-Agent string")
    query_params: Optional[Dict[str, Any]] = Field(default=None, description="Sanitized query parameters")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Selected HTTP headers")


class TraceDetails(BaseModel):
    """Distributed tracing and correlation context."""
    trace_id: Optional[str] = Field(default=None, description="Distributed trace identifier")
    span_id: Optional[str] = Field(default=None, description="Current span identifier")
    parent_span_id: Optional[str] = Field(default=None, description="Parent span identifier")
    request_id: Optional[str] = Field(default=None, description="Unique correlation or request identifier")


class ErrorDetails(BaseModel):
    """Exception and error details for forensic analysis."""
    type: str = Field(..., description="Exception class name, e.g. ValueError, HTTPException")
    message: str = Field(..., description="Exception string representation")
    stacktrace: Optional[str] = Field(default=None, description="Formatted stack traceback")


class MetadataDetails(BaseModel):
    """Runtime system metadata."""
    hostname: str = Field(default_factory=socket.gethostname)
    pid: int = Field(default_factory=os.getpid)
    thread_id: int = Field(default_factory=threading.get_ident)
    thread_name: str = Field(default_factory=lambda: threading.current_thread().name)
    sdk_name: str = Field(default="pytrace")
    sdk_version: str = Field(default="0.1.0")


class PyTraceEvent(BaseModel):
    """
    Standardized, lossless structured event model for PyTrace telemetry.
    Compatible with Fluent Bit JSON parser, Kafka ingestion, and universal preprocessing.
    """
    timestamp: str = Field(default_factory=utc_now_iso, description="ISO-8601 UTC timestamp")
    service: str = Field(default="default-service", description="Service or application name")
    environment: str = Field(default="development", description="Environment: production, staging, development")
    framework: str = Field(default="fastapi", description="Framework name: fastapi, flask, django, standalone")
    event: EventDetails = Field(default_factory=EventDetails)
    http: Optional[HttpDetails] = Field(default=None)
    duration_ms: Optional[float] = Field(default=None, description="Execution or request duration in milliseconds")
    trace: Optional[TraceDetails] = Field(default=None)
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary custom key-value attributes")
    error: Optional[ErrorDetails] = Field(default=None)
    metadata: MetadataDetails = Field(default_factory=MetadataDetails)
    raw: Optional[Dict[str, Any]] = Field(default=None, description="Optional raw payload or original input for lossless tracing")

    def to_dict(self, exclude_none: bool = False) -> Dict[str, Any]:
        """Convert model to dictionary."""
        return self.model_dump(exclude_none=exclude_none)

    def to_json(self, exclude_none: bool = False) -> str:
        """Convert model to JSON string."""
        return self.model_dump_json(exclude_none=exclude_none)
