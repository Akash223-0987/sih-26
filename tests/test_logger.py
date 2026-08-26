import logging
import pytest
from typing import List
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

    event = log.info("Payment initiated", order_id="ORD-999", amount=120.50)

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

    set_current_trace_id("trace_1234567890abcdef12345678")
    set_current_request_id("req_abc")
    set_request_attributes({"session_id": "sess_888"})

    log.warn("High login attempts detected", username="alice", attempts=5)

    assert len(exp.events) == 1
    ev = exp.events[0]
    assert ev.event.severity == "WARNING"
    assert ev.trace.trace_id == "trace_1234567890abcdef12345678"
    assert ev.trace.request_id == "req_abc"
    assert ev.attributes["session_id"] == "sess_888"
    assert ev.attributes["username"] == "alice"
    assert ev.attributes["attempts"] == 5

    # cleanup
    set_current_trace_id(None)
    set_current_request_id(None)
    set_request_attributes({})


def test_structured_logger_exception():
    exp = MemoryExporter()
    cfg = PyTraceConfig(service_name="checkout-service")
    log = StructuredLogger(name="test.logger", config=cfg, exporter=exp)

    try:
        1 / 0
    except ZeroDivisionError as e:
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
