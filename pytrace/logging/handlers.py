"""
PyTrace Standard Library Logging Handler.
Enables seamless integration with existing Python `logging` without refactoring legacy calls.
"""

from __future__ import annotations

import logging
from typing import Optional
from pytrace.exporters.base import BaseExporter
from pytrace.logging.logger import StructuredLogger, logger


class PyTraceHandler(logging.Handler):
    """
    Custom logging.Handler that converts standard logging.LogRecord instances
    into PyTrace structured JSON telemetry events.
    """

    def __init__(self, structured_logger: Optional[StructuredLogger] = None):
        super().__init__()
        self.structured_logger = structured_logger or logger

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            level_name = record.levelname.upper()

            # Extract any extra attributes passed to log record
            extra_attrs = {}
            standard_record_attrs = {
                "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
                "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread", "threadName",
                "processName", "process", "message",
            }
            for k, v in record.__dict__.items():
                if k not in standard_record_attrs and not k.startswith("_"):
                    extra_attrs[k] = v

            extra_attrs["logger_name"] = record.name
            extra_attrs["source_file"] = f"{record.filename}:{record.lineno}"

            exc_info = record.exc_info if record.exc_info else None

            if level_name == "DEBUG":
                self.structured_logger.debug(msg, exc_info=exc_info, **extra_attrs)
            elif level_name in ("WARNING", "WARN"):
                self.structured_logger.warning(msg, exc_info=exc_info, **extra_attrs)
            elif level_name == "ERROR":
                self.structured_logger.error(msg, exc_info=exc_info, **extra_attrs)
            elif level_name in ("CRITICAL", "FATAL"):
                self.structured_logger.critical(msg, exc_info=exc_info, **extra_attrs)
            else:
                self.structured_logger.info(msg, exc_info=exc_info, **extra_attrs)
        except Exception:
            self.handleError(record)
