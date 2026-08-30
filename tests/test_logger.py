import logging
import sys
from typing import Any, cast, List
from unittest.mock import MagicMock, patch

import pytest

from pytrace.config import PyTraceConfig
from pytrace.context.request import set_current_request_id, set_request_attributes
from pytrace.context.trace import set_current_trace_id
from pytrace.exporters.base import BaseExporter
from pytrace.logging.handlers import PyTraceHandler
from pytrace.logging.logger import StructuredLogger
from pytrace.models.event import PyTraceEvent


class MemoryExporter(BaseExporter):
    def __init__(self):
        self.events: List[PyTraceEvent] = []

    def export(self, event: PyTraceEvent) -> None:
        self.events.append(event)


def test_structured_logger_info():
    exp = MemoryExporter()
    cfg = PyTraceConfig(service_name="payment-service", environment="test")
    log = StructuredLogger(name="test.logger", config=cfg, exporter=exp)

    log.info("Payment initiated", order_id="ORD-999", amount=120.50)

    assert len(exp.events) == 1
    ev = exp.events[0]
    assert ev.service == "payment-service"
    assert ev.environment == "test"
    assert ev.event.severity == "INFO"
    assert ev.event.message == "Payment initiated"
    assert ev.attributes["order_id"] == "ORD-999"
    assert ev.attributes["amount"] == 120.50


def test_structured_logger_with_context():
    exp = MemoryExporter()
    cfg = PyTraceConfig(service_name="auth-service")
    log = StructuredLogger(name="test.logger", config=cfg, exporter=exp)

    t_tok = set_current_trace_id("trace_1234567890abcdef12345678")
    r_tok = set_current_request_id("req_abc")
    a_tok = set_request_attributes({"session_id": "sess_888"})

    try:
        log.warn("High login attempts detected", username="alice", attempts=5)

        assert len(exp.events) == 1
        ev = exp.events[0]
        assert ev.event.severity == "WARNING"
        assert ev.trace.trace_id == "trace_1234567890abcdef12345678"
        assert ev.trace.request_id == "req_abc"
        assert ev.attributes["session_id"] == "sess_888"
        assert ev.attributes["username"] == "alice"
        assert ev.attributes["attempts"] == 5
    finally:
        # cleanup
        set_current_trace_id(t_tok)
        set_current_request_id(r_tok)
        set_request_attributes(a_tok)



def test_structured_logger_exception():
    exp = MemoryExporter()
    cfg = PyTraceConfig(service_name="checkout-service")
    log = StructuredLogger(name="test.logger", config=cfg, exporter=exp)

    try:
        1 / 0
    except ZeroDivisionError:
        log.exception("Division calculation failed", cart_id="cart_01")

    assert len(exp.events) == 1
    ev = exp.events[0]
    assert ev.event.severity == "ERROR"
    assert ev.error is not None
    assert ev.error.type == "ZeroDivisionError"
    assert "division by zero" in ev.error.message
    assert ev.error.stacktrace is not None
    assert "ZeroDivisionError" in ev.error.stacktrace


def test_pytrace_handler_for_stdlib_logging():
    exp = MemoryExporter()
    cfg = PyTraceConfig(service_name="legacy-app")
    log = StructuredLogger(name="test.logger", config=cfg, exporter=exp)
    handler = PyTraceHandler(structured_logger=log)

    test_std_logger = logging.getLogger("legacy_module")
    test_std_logger.setLevel(logging.INFO)
    test_std_logger.addHandler(handler)

    test_std_logger.info("Legacy log message with extra", extra={"customer_tier": "gold"})

    assert len(exp.events) == 1
    ev = exp.events[0]
    assert ev.event.message == "Legacy log message with extra"
    assert ev.attributes["customer_tier"] == "gold"
    assert ev.attributes["logger_name"] == "legacy_module"


# ==============================================================================
# EDGE CASES & BOUNDARY VALUES
# ==============================================================================

def test_structured_logger_levels_and_thresholds():
    """Test logger thresholds, log level validation, and unexpected severities."""
    exp = MemoryExporter()
    cfg = PyTraceConfig(log_level="WARNING")
    log = StructuredLogger(config=cfg, exporter=exp)

    # Below log level threshold
    log.info("info message")
    assert len(exp.events) == 0

    # At/Above log level threshold
    log.warning("warning message")
    assert len(exp.events) == 1
    assert exp.events[0].event.severity == "WARNING"

    # Unexpected/Unknown log level config threshold (defaults config threshold to INFO/20)
    cfg_unknown = PyTraceConfig(log_level="UNKNOWN_LEVEL")
    log_unknown = StructuredLogger(config=cfg_unknown, exporter=exp)

    exp.events.clear()
    log_unknown.debug("debug message")  # 10 < 20
    assert len(exp.events) == 0

    log_unknown.info("info message")  # 20 >= 20
    assert len(exp.events) == 1
    assert exp.events[0].event.severity == "INFO"


def test_structured_logger_exception_capture_edge_cases():
    """Test logger exception and traceback capture under diverse format inputs."""
    exp = MemoryExporter()
    log = StructuredLogger(exporter=exp)

    # 1. exc_info is an exception instance
    exc = ValueError("Instance error message")
    log.error("Error occurred", exc_info=exc)
    assert len(exp.events) == 1
    assert exp.events[0].error.type == "ValueError"
    assert exp.events[0].error.message == "Instance error message"

    # 2. exc_info is True but no active exception exists
    exp.events.clear()
    log.error("No active exception exists", exc_info=True)
    assert len(exp.events) == 1
    assert exp.events[0].error is None

    # 3. exc_info is a 3-tuple (type, value, traceback)
    exp.events.clear()
    try:
        raise KeyError("Key missing error")
    except KeyError:
        exc_type, exc_val, exc_tb = sys.exc_info()
        log.error("Tuple error", exc_info=(exc_type, exc_val, exc_tb))
    assert len(exp.events) == 1
    assert exp.events[0].error.type == "KeyError"
    assert "KeyError" in exp.events[0].error.stacktrace

    # 4. exc_info is a 3-tuple of (None, None, None)
    exp.events.clear()
    log.error("None tuple error", exc_info=(None, None, None))
    assert len(exp.events) == 1
    assert exp.events[0].error.type == "Exception"
    assert exp.events[0].error.message == ""
    assert exp.events[0].error.stacktrace is None

    # 5. exc_info is unexpected type (like an integer)
    exp.events.clear()
    log.error("Unexpected exc_info type", exc_info=cast(Any, 42))
    assert len(exp.events) == 1
    assert exp.events[0].error is None


def test_pytrace_handler_stdlib_logging_failures():
    """Test PyTraceHandler integration and its handleError fallback execution."""
    exp = MemoryExporter()
    log = StructuredLogger(exporter=exp)
    handler = PyTraceHandler(structured_logger=log)

    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Stdlib log message",
        args=(),
        exc_info=None
    )
    # Set extra attributes
    record.__dict__["extra_key"] = "extra_val"
    record.__dict__["_private_key"] = "private"  # Should be ignored (starts with _)

    handler.emit(record)
    assert len(exp.events) == 1
    assert exp.events[0].event.message == "Stdlib log message"
    assert exp.events[0].attributes["extra_key"] == "extra_val"
    assert "_private_key" not in exp.events[0].attributes

    # Exception handling: logger.info raises Exception
    bad_logger = MagicMock()
    bad_logger.info.side_effect = Exception("Emit failed")
    handler_bad = PyTraceHandler(structured_logger=bad_logger)

    with patch.object(handler_bad, "handleError") as mock_handle_error:
        handler_bad.emit(record)
        mock_handle_error.assert_called_once_with(record)
