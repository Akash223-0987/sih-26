import io
import sys
import tempfile
import threading
import urllib.request
import urllib.error
import contextvars
import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from pytrace.config import PyTraceConfig, get_config, set_config
from pytrace.context.request import (
    generate_request_id,
    get_request_attributes,
    set_request_attributes,
    update_request_attribute,
)
from pytrace.context.trace import (
    format_w3c_traceparent,
    generate_span_id,
    generate_trace_id,
    get_current_parent_span_id,
    get_current_span_id,
    get_current_trace_id,
    parse_w3c_traceparent,
    reset_trace_id,
    set_current_parent_span_id,
    set_current_span_id,
    set_current_trace_id,
)
from pytrace.exporters.base import BaseExporter
from pytrace.exporters.composite import CompositeExporter, create_exporter_from_config
from pytrace.exporters.file import FileExporter
from pytrace.exporters.fluentbit import FluentBitExporter
from pytrace.exporters.http import HttpExporter
from pytrace.exporters.stdout import StdoutExporter
from pytrace.instrumentation.fastapi import PyTraceMiddleware
from pytrace.logging.handlers import PyTraceHandler
from pytrace.logging.logger import StructuredLogger
from pytrace.models.event import (
    ErrorDetails,
    EventDetails,
    HttpDetails,
    PyTraceEvent,
)


class MemoryExporter(BaseExporter):
    """Memory exporter for validating exported telemetry events in tests."""
    def __init__(self):
        self.events: List[PyTraceEvent] = []

    def export(self, event: PyTraceEvent) -> None:
        self.events.append(event)


# ==============================================================================
# CONFIGURATION EDGE CASES
# ==============================================================================

def test_config_empty_values():
    """Test PyTraceConfig with empty string settings (empty inputs)."""
    config = PyTraceConfig(service_name="", environment="", log_dir="", log_file="")
    assert config.service_name == ""
    assert config.environment == ""
    assert config.log_dir == ""
    assert config.log_file == ""


def test_config_invalid_types():
    """Test PyTraceConfig with invalid data types (invalid inputs)."""
    with pytest.raises(ValidationError):
        PyTraceConfig(fluentbit_port="not-an-integer")  # type: ignore

    with pytest.raises(ValidationError):
        PyTraceConfig(sample_rate="not-a-float")  # type: ignore


def test_global_config_lifecycle():
    """Test retrieving, setting, and resetting the global configuration object."""
    orig_config = get_config()
    new_config = PyTraceConfig(service_name="custom-global-service")
    set_config(new_config)
    assert get_config().service_name == "custom-global-service"

    # None value testing for set_config
    set_config(None)  # type: ignore
    assert get_config().service_name == "default-service"

    # Restore original config
    set_config(orig_config)


# ==============================================================================
# CONTEXT MANAGEMENT EDGE CASES
# ==============================================================================

def test_trace_generation_extreme():
    """Test key generation with empty and extremely long inputs."""
    # Empty prefix request ID (boundary test)
    rid_empty = generate_request_id(prefix="")
    assert len(rid_empty) == 16

    # Extremely large input prefix (maximum boundary test)
    long_prefix = "a" * 10000
    rid_large = generate_request_id(prefix=long_prefix)
    assert rid_large.startswith(long_prefix)
    assert len(rid_large) == 10016


def test_trace_context_get_set_reset_tokens():
    """Test setting, retrieving, and resetting trace context variables with None and invalid tokens."""
    # None values
    token = set_current_trace_id(None)
    assert get_current_trace_id() is None
    reset_trace_id(token)

    token_span = set_current_span_id(None)
    assert get_current_span_id() is None
    set_current_span_id(token_span)

    token_parent = set_current_parent_span_id(None)
    assert get_current_parent_span_id() is None
    set_current_parent_span_id(token_parent)

    # Exception handling: resetting context using a token from a different ContextVar
    other_var = contextvars.ContextVar("other_var")
    token_other = other_var.set("val")
    with pytest.raises(ValueError):
        reset_trace_id(token_other)


def test_w3c_traceparent_parse_and_format_edge_cases():
    """Test parsing and formatting traceparent headers under empty, None, and malformed cases."""
    # Empty inputs
    parsed_trace, parsed_parent = parse_w3c_traceparent("")
    assert parsed_trace is None
    assert parsed_parent is None

    # None values
    parsed_trace, parsed_parent = parse_w3c_traceparent(None)  # type: ignore
    assert parsed_trace is None
    assert parsed_parent is None

    # Invalid inputs and data types
    parsed_trace, parsed_parent = parse_w3c_traceparent(12345)  # type: ignore
    assert parsed_trace is None
    assert parsed_parent is None

    # Malformed data cases
    # 1. Missing parts (only 3 parts instead of 4)
    parsed_trace, parsed_parent = parse_w3c_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7")
    assert parsed_trace is None
    assert parsed_parent is None

    # 2. Trace ID wrong length (31 chars)
    parsed_trace, parsed_parent = parse_w3c_traceparent("00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01")
    assert parsed_trace is None
    assert parsed_parent is None

    # 3. Span ID wrong length (15 chars)
    parsed_trace, parsed_parent = parse_w3c_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b-01")
    assert parsed_trace is None
    assert parsed_parent is None


def test_request_attributes_edge_cases():
    """Test updating request context attributes with duplicate keys, None, and invalid types."""
    # Duplicate key updates
    token = set_request_attributes({"key": "value"})
    update_request_attribute("key", "new_value")
    assert get_request_attributes() == {"key": "new_value"}

    # Unexpected/additional keys
    update_request_attribute("new_key", 42)
    assert get_request_attributes() == {"key": "new_value", "new_key": 42}

    # None values and invalid types
    with pytest.raises(AttributeError):
        set_request_attributes(None)  # type: ignore

    with pytest.raises(AttributeError):
        set_request_attributes("not-a-dict")  # type: ignore

    # Reset
    set_request_attributes(token)


# ==============================================================================
# MODEL EDGE CASES
# ==============================================================================

def test_pytrace_event_validation_boundaries_and_types():
    """Test PyTraceEvent boundary constraints, validation errors, and invalid types."""
    # Minimum boundary values
    event_min = PyTraceEvent(duration_ms=0.0)
    assert event_min.duration_ms == 0.0

    # Negative values (just below boundaries)
    event_neg = PyTraceEvent(duration_ms=-1.5)
    assert event_neg.duration_ms == -1.5

    # Maximum boundary values
    event_max = PyTraceEvent(duration_ms=999999999.9)
    assert event_max.duration_ms == 999999999.9

    # Very large inputs (very long service string)
    huge_service = "s" * 10000
    event_large = PyTraceEvent(service=huge_service)
    assert event_large.service == huge_service

    # Very small inputs (single character service)
    event_small = PyTraceEvent(service="a")
    assert event_small.service == "a"

    # Invalid inputs and data types
    with pytest.raises(ValidationError):
        PyTraceEvent(duration_ms="not-a-float")  # type: ignore

    # Missing fields
    with pytest.raises(ValidationError):
        # type and message are required fields in ErrorDetails
        ErrorDetails(type="ValueError")  # type: ignore

    # Malformed data (non-serializable object inside dict attributes)
    non_serializable = threading.current_thread()
    event_malformed = PyTraceEvent(attributes={"thread": non_serializable})  # type: ignore

    # Should raise error on JSON serialization due to the non-serializable object
    with pytest.raises(Exception):
        event_malformed.to_json()


# ==============================================================================
# EXPORTER EDGE CASES
# ==============================================================================

def test_stdout_exporter_json_and_pretty_edge_cases():
    """Test StdoutExporter pretty format logic with None variables and error resilience."""
    # None values: duration_ms = None, http = None
    buf_pretty = io.StringIO()
    exporter_pretty = StdoutExporter(json_format=False, stream=buf_pretty)
    event_none = PyTraceEvent(
        event=EventDetails(message="pretty-test", severity="INFO"),
        http=None,
        duration_ms=None
    )
    exporter_pretty.export(event_none)
    assert "[INFO]" in buf_pretty.getvalue()
    assert "pretty-test" in buf_pretty.getvalue()

    # HttpDetails present but duration_ms is None (boundary case)
    buf_pretty2 = io.StringIO()
    exporter_pretty2 = StdoutExporter(json_format=False, stream=buf_pretty2)
    event_http_no_duration = PyTraceEvent(
        event=EventDetails(message="pretty-test-http", severity="INFO"),
        http=HttpDetails(method="GET", path="/test"),
        duration_ms=None
    )
    exporter_pretty2.export(event_http_no_duration)
    assert "[GET /test]" in buf_pretty2.getvalue()

    # Exception handling: write fails (e.g. stream raises Exception)
    bad_stream = MagicMock()
    bad_stream.write.side_effect = Exception("Write failed")
    exporter_bad = StdoutExporter(stream=bad_stream)

    # Should gracefully capture exception internally and log to sys.stderr
    with patch("sys.stderr.write") as mock_stderr:
        exporter_bad.export(event_none)
        mock_stderr.assert_called_once()
        assert "StdoutExporter error" in mock_stderr.call_args[0][0]


def test_file_exporter_error_handling():
    """Test FileExporter resilient fallback when target paths are invalid or unwritable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Pass a directory path instead of a file path, causing write permission exception
        exporter = FileExporter(filepath=tmpdir)
        event = PyTraceEvent(event=EventDetails(message="should fail writing to directory"))

        with patch("sys.stderr.write") as mock_stderr:
            exporter.export(event)
            mock_stderr.assert_called_once()
            assert "FileExporter error writing to" in mock_stderr.call_args[0][0]


def test_http_exporter_failures():
    """Test HttpExporter urllib exception resilience on malformed endpoints."""
    event = PyTraceEvent(event=EventDetails(message="http export test"))

    # Exception handling: invalid URL or network exceptions
    exporter_bad = HttpExporter(endpoint_url="invalid-url")
    exporter_bad.export(event)  # Should fail silently

    exporter_none = HttpExporter(endpoint_url=None)  # type: ignore
    exporter_none.export(event)  # Should fail silently


@patch("socket.socket")
def test_fluentbit_exporter_mocked(mock_socket_class):
    """Test FluentBitExporter TCP socket connection failures and re-connect operations."""
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket

    # 1. Connection failure
    mock_socket.connect.side_effect = Exception("Connection refused")
    exporter = FluentBitExporter(host="127.0.0.1", port=24224)
    event = PyTraceEvent(event=EventDetails(message="fluentbit log"))

    exporter.export(event)  # Should fail silently
    assert exporter._sock is None

    # 2. Connection success
    mock_socket.connect.side_effect = None
    exporter_success = FluentBitExporter(host="127.0.0.1", port=24224)
    exporter_success.export(event)

    assert exporter_success._sock is not None
    mock_socket.sendall.assert_called_once()

    # 3. Connection dropped, sendall raises exception, reconnect succeeds
    mock_socket.sendall.reset_mock()
    mock_socket.sendall.side_effect = [Exception("Socket closed"), None]

    exporter_success.export(event)
    # The first sendall fails, closes the socket, reconnects, then calls sendall again
    assert mock_socket.sendall.call_count == 2
    mock_socket.close.assert_called_once()


def test_composite_exporter_and_factory_edge_cases():
    """Test composite pipeline factory with empty, whitespace, and unknown targets."""
    # Empty string configuration fallback
    cfg_empty = PyTraceConfig(exporter_type="")
    exporter_empty = create_exporter_from_config(cfg_empty)
    assert isinstance(exporter_empty, StdoutExporter)

    # Whitespaces and multiple entries parsing
    cfg_spaces = PyTraceConfig(exporter_type="  file ,  stdout  ", log_dir="temp_logs")
    exporter_spaces = create_exporter_from_config(cfg_spaces)
    assert isinstance(exporter_spaces, CompositeExporter)
    assert len(exporter_spaces.exporters) == 2
    assert isinstance(exporter_spaces.exporters[0], FileExporter)
    assert isinstance(exporter_spaces.exporters[1], StdoutExporter)

    # Unknown exporter config targets
    cfg_unknown = PyTraceConfig(exporter_type="unknown_target")
    exporter_unknown = create_exporter_from_config(cfg_unknown)
    assert isinstance(exporter_unknown, StdoutExporter)

    # Composite pipeline exceptions tolerance
    bad_exporter = MagicMock()
    bad_exporter.export.side_effect = Exception("Fail")
    good_exporter = MagicMock()

    comp = CompositeExporter([bad_exporter, good_exporter])
    event = PyTraceEvent()
    comp.export(event)  # Should not raise exception
    bad_exporter.export.assert_called_once_with(event)
    good_exporter.export.assert_called_once_with(event)

    # Flush/close operations tolerance
    bad_exporter.flush.side_effect = Exception("Flush fail")
    bad_exporter.close.side_effect = Exception("Close fail")
    comp.flush()
    comp.close()
    bad_exporter.flush.assert_called_once()
    bad_exporter.close.assert_called_once()
    good_exporter.flush.assert_called_once()
    good_exporter.close.assert_called_once()


# ==============================================================================
# LOGGER EDGE CASES
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
    log.error("Unexpected exc_info type", exc_info=42)  # type: ignore
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


# ==============================================================================
# FASTAPI MIDDLEWARE & ASGI EDGE CASES
# ==============================================================================

def test_fastapi_middleware_non_http_scope():
    """Test PyTraceMiddleware with non-http scope types like websockets."""
    called = []
    async def mock_app(scope, receive, send):
        called.append((scope, receive, send))

    middleware = PyTraceMiddleware(app=mock_app)

    scope = {"type": "websocket"}
    receive = MagicMock()
    send = MagicMock()

    asyncio.run(middleware(scope, receive, send))
    assert len(called) == 1
    assert called[0] == (scope, receive, send)


def test_fastapi_middleware_client_ip_edge_cases():
    """Test PyTraceMiddleware parsing client IP from different ASGI scope structures."""
    exporter = MemoryExporter()
    config = PyTraceConfig(service_name="test-api")

    async def mock_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def dummy_receive():
        return {}

    async def dummy_send(message):
        pass

    middleware = PyTraceMiddleware(app=mock_app, config=config, exporter=exporter)

    # 1. client is None
    scope_none = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "client": None,
        "headers": []
    }
    asyncio.run(middleware(scope_none, dummy_receive, dummy_send))
    assert len(exporter.events) == 1
    assert exporter.events[0].http.client_ip == "127.0.0.1"

    # 2. client is empty
    exporter.events.clear()
    scope_empty = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "client": (),
        "headers": []
    }
    asyncio.run(middleware(scope_empty, dummy_receive, dummy_send))
    assert len(exporter.events) == 1
    assert exporter.events[0].http.client_ip == "127.0.0.1"

    # 3. client is normal tuple
    exporter.events.clear()
    scope_normal = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "client": ("192.168.1.50", 54321),
        "headers": []
    }
    asyncio.run(middleware(scope_normal, dummy_receive, dummy_send))
    assert len(exporter.events) == 1
    assert exporter.events[0].http.client_ip == "192.168.1.50"


def test_fastapi_middleware_header_decoding_resilience():
    """Test PyTraceMiddleware resilience when request headers fail to decode."""
    exporter = MemoryExporter()

    async def mock_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def dummy_send(message):
        pass

    middleware = PyTraceMiddleware(app=mock_app, exporter=exporter)

    # Header name/value contains invalid type (raising exception on decode)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "client": ("127.0.0.1", 80),
        "headers": [
            (b"user-agent", b"PyTraceAgent"),
            (None, b"invalid-header-name"),  # Will raise AttributeError on decode
            (b"x-custom-header", 12345),  # Will raise AttributeError on decode
        ]
    }

    asyncio.run(middleware(scope, None, dummy_send))  # type: ignore

    assert len(exporter.events) == 1
    ev = exporter.events[0]
    assert ev.http.user_agent == "PyTraceAgent"
    assert "x-custom-header" not in ev.http.headers if ev.http.headers else True


def test_fastapi_middleware_exception_and_error_handling():
    """Test PyTraceMiddleware catching, logging, and re-raising exceptions raised by the app."""
    exporter = MemoryExporter()

    async def failing_app(scope, receive, send):
        raise RuntimeError("Database connection timed out")

    async def dummy_send(message):
        pass

    middleware = PyTraceMiddleware(app=failing_app, exporter=exporter)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/submit",
        "client": ("127.0.0.1", 80),
        "headers": []
    }

    # The middleware should re-raise the exception
    with pytest.raises(RuntimeError):
        asyncio.run(middleware(scope, None, dummy_send))  # type: ignore

    assert len(exporter.events) == 1
    ev = exporter.events[0]
    assert ev.event.severity == "ERROR"
    assert ev.event.action == "failed"
    assert ev.http.status_code == 500
    assert ev.error is not None
    assert ev.error.type == "RuntimeError"
    assert "Database connection timed out" in ev.error.message
    assert ev.error.stacktrace is not None


def test_fastapi_middleware_send_wrapper_missing_headers():
    """Test PyTraceMiddleware send_wrapper when the ASGI response does not contain the headers key."""
    exporter = MemoryExporter()

    captured_messages = []
    async def mock_send(message):
        captured_messages.append(message)

    async def mock_app(scope, receive, send):
        # We don't specify "headers" key in the response message
        await send({"type": "http.response.start", "status": 201})

    middleware = PyTraceMiddleware(app=mock_app, exporter=exporter)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/no-headers",
        "headers": []
    }

    asyncio.run(middleware(scope, None, mock_send))  # type: ignore

    assert len(exporter.events) == 1
    assert exporter.events[0].http.status_code == 201

    # Check that headers were injected even though the original message had no headers
    assert len(captured_messages) == 1
    msg = captured_messages[0]
    headers_dict = dict(msg["headers"])
    assert b"x-request-id" in headers_dict
    assert b"x-trace-id" in headers_dict
    assert b"traceparent" in headers_dict
