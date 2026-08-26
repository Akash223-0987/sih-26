"""
PyTrace Structured Logger.
Provides an intuitive, high-performance explicit logging API with automatic context binding.
"""

from __future__ import annotations

import sys
import traceback
from typing import Any, Dict, Optional, Union
from pytrace.config import PyTraceConfig, get_config
from pytrace.context.request import get_current_request_id, get_request_attributes
from pytrace.context.trace import (
    get_current_parent_span_id,
    get_current_span_id,
    get_current_trace_id,
)
from pytrace.exporters.base import BaseExporter
from pytrace.exporters.composite import create_exporter_from_config
from pytrace.models.event import (
    ErrorDetails,
    EventDetails,
    MetadataDetails,
    PyTraceEvent,
    TraceDetails,
)

_LEVEL_MAP = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "WARN": 30,
    "ERROR": 40,
    "CRITICAL": 50,
    "FATAL": 50,
}


class StructuredLogger:
    """
    Structured logger that attaches distributed trace context, request ID,
    runtime metadata, and arbitrary business attributes to telemetry events.
    """

    def __init__(
        self,
        name: str = "pytrace",
        config: Optional[PyTraceConfig] = None,
        exporter: Optional[BaseExporter] = None,
    ):
        self.name = name
        self.config = config or get_config()
        self.exporter = exporter or create_exporter_from_config(self.config)

    def _should_log(self, severity: str) -> bool:
        """Check if severity meets configured threshold."""
        configured_threshold = _LEVEL_MAP.get(self.config.log_level.upper(), 20)
        message_level = _LEVEL_MAP.get(severity.upper(), 20)
        return message_level >= configured_threshold

    def _emit(
        self,
        severity: str,
        message: str,
        action: Optional[str] = None,
        exc_info: Optional[Union[bool, BaseException, tuple]] = None,
        event_type: str = "log",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> PyTraceEvent:
        """Construct and export a PyTraceEvent."""
        if not self._should_log(severity):
            return None  # type: ignore

        # Capture error details if present
        error_details: Optional[ErrorDetails] = None
        if exc_info:
            if isinstance(exc_info, BaseException):
                err_type = type(exc_info).__name__
                err_msg = str(exc_info)
                err_tb = "".join(traceback.format_exception(type(exc_info), exc_info, exc_info.__traceback__))
                error_details = ErrorDetails(type=err_type, message=err_msg, stacktrace=err_tb)
            elif isinstance(exc_info, tuple) and len(exc_info) == 3:
                err_cls, err_inst, tb = exc_info
                err_type = err_cls.__name__ if err_cls else "Exception"
                err_msg = str(err_inst) if err_inst else ""
                err_tb = "".join(traceback.format_exception(err_cls, err_inst, tb)) if tb else None
                error_details = ErrorDetails(type=err_type, message=err_msg, stacktrace=err_tb)
            elif exc_info is True:
                err_cls, err_inst, tb = sys.exc_info()
                if err_cls:
                    err_type = err_cls.__name__
                    err_msg = str(err_inst) if err_inst else ""
                    err_tb = "".join(traceback.format_exception(err_cls, err_inst, tb))
                    error_details = ErrorDetails(type=err_type, message=err_msg, stacktrace=err_tb)

        # Merge request context attributes with log-specific attributes
        merged_attributes = get_request_attributes()
        if attributes:
            merged_attributes.update(attributes)

        # Extract current trace & request context
        trace_id = get_current_trace_id()
        span_id = get_current_span_id()
        parent_span_id = get_current_parent_span_id()
        request_id = get_current_request_id()

        trace_details: Optional[TraceDetails] = None
        if trace_id or request_id or span_id:
            trace_details = TraceDetails(
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                request_id=request_id,
            )

        event = PyTraceEvent(
            service=self.config.service_name,
            environment=self.config.environment,
            framework="fastapi",
            event=EventDetails(
                type=event_type,
                action=action,
                severity=severity.upper(),
                message=message,
            ),
            trace=trace_details,
            attributes=merged_attributes,
            error=error_details,
            metadata=MetadataDetails(),
        )

        try:
            self.exporter.export(event)
        except Exception:
            pass

        return event

    def debug(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Log a DEBUG severity event."""
        action = kwargs.pop("action", None)
        exc_info = kwargs.pop("exc_info", None)
        return self._emit("DEBUG", message, action=action, exc_info=exc_info, attributes=kwargs)

    def info(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Log an INFO severity event."""
        action = kwargs.pop("action", None)
        exc_info = kwargs.pop("exc_info", None)
        return self._emit("INFO", message, action=action, exc_info=exc_info, attributes=kwargs)

    def warning(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Log a WARNING severity event."""
        action = kwargs.pop("action", None)
        exc_info = kwargs.pop("exc_info", None)
        return self._emit("WARNING", message, action=action, exc_info=exc_info, attributes=kwargs)

    def warn(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Alias for warning."""
        return self.warning(message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Log an ERROR severity event."""
        action = kwargs.pop("action", None)
        exc_info = kwargs.pop("exc_info", None)
        return self._emit("ERROR", message, action=action, exc_info=exc_info, attributes=kwargs)

    def critical(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Log a CRITICAL severity event."""
        action = kwargs.pop("action", None)
        exc_info = kwargs.pop("exc_info", None)
        return self._emit("CRITICAL", message, action=action, exc_info=exc_info, attributes=kwargs)

    def exception(self, message: str, **kwargs: Any) -> Optional[PyTraceEvent]:
        """Log an ERROR severity event with captured exception traceback."""
        action = kwargs.pop("action", None)
        exc_info = kwargs.pop("exc_info", True)
        return self._emit("ERROR", message, action=action, exc_info=exc_info, attributes=kwargs)


# Global singleton logger
logger = StructuredLogger(name="pytrace.global")


def get_logger(name: str = "pytrace") -> StructuredLogger:
    """Retrieve or construct a named StructuredLogger."""
    return StructuredLogger(name=name)
