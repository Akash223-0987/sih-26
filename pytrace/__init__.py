"""
PyTrace: Developer Observability & Telemetry Framework.
"""

from pytrace.config import PyTraceConfig, get_config, set_config
from pytrace.context.request import (
    generate_request_id,
    get_current_request_id,
    update_request_attribute,
)
from pytrace.context.trace import (
    generate_span_id,
    generate_trace_id,
    get_current_parent_span_id,
    get_current_span_id,
    get_current_trace_id,
)
from pytrace.instrumentation.fastapi import PyTrace, PyTraceMiddleware
from pytrace.logging.handlers import PyTraceHandler
from pytrace.logging.logger import StructuredLogger, get_logger, logger
from pytrace.models.event import (
    ErrorDetails,
    EventDetails,
    HttpDetails,
    MetadataDetails,
    PyTraceEvent,
    TraceDetails,
)

__version__ = "0.1.0"

__all__ = [
    "PyTrace",
    "PyTraceMiddleware",
    "logger",
    "get_logger",
    "StructuredLogger",
    "PyTraceHandler",
    "PyTraceConfig",
    "get_config",
    "set_config",
    "PyTraceEvent",
    "EventDetails",
    "HttpDetails",
    "TraceDetails",
    "ErrorDetails",
    "MetadataDetails",
    "generate_trace_id",
    "generate_span_id",
    "generate_request_id",
    "get_current_trace_id",
    "get_current_span_id",
    "get_current_parent_span_id",
    "get_current_request_id",
    "update_request_attribute",
    "__version__",
]
