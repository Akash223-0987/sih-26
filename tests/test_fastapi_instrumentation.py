import asyncio
from typing import List, Any, cast
from unittest.mock import MagicMock
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from pytrace.config import PyTraceConfig
from pytrace.context.request import update_request_attribute
from pytrace.exporters.base import BaseExporter
from pytrace.instrumentation.fastapi import PyTrace, PyTraceMiddleware
from pytrace.logging.logger import StructuredLogger
from pytrace.models.event import PyTraceEvent


class RecordingExporter(BaseExporter):
    def __init__(self):
        self.events: List[PyTraceEvent] = []

    def export(self, event: PyTraceEvent) -> None:
        self.events.append(event)


@pytest.fixture
def recording_setup():
    exporter = RecordingExporter()
    config = PyTraceConfig(service_name="test-api", environment="test")
    app = FastAPI(title="TestApp")
    PyTrace(app=app, config=config, exporter=exporter)
    custom_logger = StructuredLogger(name="test-api-logger", config=config, exporter=exporter)

    @app.get("/users/{user_id}")
    def get_user(user_id: int, filter_role: str = "all"):
        update_request_attribute("user_tier", "premium")
        custom_logger.info("Fetched user profile from DB", user_id=user_id, status="active")
        return {"id": user_id, "name": "Alice", "role": filter_role}

    @app.get("/error-endpoint")
    def fail():
        raise RuntimeError("Database connection pool exhausted")

    @app.get("/client-error")
    def not_found():
        raise HTTPException(status_code=404, detail="Resource not found")

    client = TestClient(app, raise_server_exceptions=False)
    return client, exporter


def test_fastapi_auto_instrumentation_success(recording_setup):
    client, exporter = recording_setup

    response = client.get("/users/42?filter_role=admin", headers={"User-Agent": "PyTraceTestAgent/1.0"})

    assert response.status_code == 200
    assert response.json() == {"id": 42, "name": "Alice", "role": "admin"}

    # Validate response headers
    assert "x-request-id" in response.headers
    assert "x-trace-id" in response.headers
    assert "traceparent" in response.headers

    req_id = response.headers["x-request-id"]
    trace_id = response.headers["x-trace-id"]

    # We expect 2 events:
    # 1. Explicit business log: "Fetched user profile from DB"
    # 2. Automatic HTTP request event: "GET /users/42 completed with 200..."
    assert len(exporter.events) == 2

    biz_event = exporter.events[0]
    http_event = exporter.events[1]

    # Verify explicit event has inherited trace context & request attributes
    assert biz_event.event.type == "log"
    assert biz_event.event.message == "Fetched user profile from DB"
    assert biz_event.trace.trace_id == trace_id
    assert biz_event.trace.request_id == req_id
    assert biz_event.attributes["user_id"] == 42
    assert biz_event.attributes["user_tier"] == "premium"

    # Verify auto-captured HTTP event
    assert http_event.event.type == "http_request"
    assert http_event.event.severity == "INFO"
    assert http_event.http.method == "GET"
    assert http_event.http.path == "/users/42"
    assert http_event.http.status_code == 200
    assert http_event.http.user_agent == "PyTraceTestAgent/1.0"
    assert http_event.http.query_params == {"filter_role": "admin"}
    assert http_event.duration_ms > 0
    assert http_event.trace.trace_id == trace_id
    assert http_event.trace.request_id == req_id


def test_fastapi_traceparent_header_propagation(recording_setup):
    client, exporter = recording_setup

    incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    incoming_parent_span = "00f067aa0ba902b7"
    w3c_header = f"00-{incoming_trace_id}-{incoming_parent_span}-01"

    response = client.get("/users/1", headers={"traceparent": w3c_header, "x-request-id": "custom-req-999"})

    assert response.status_code == 200
    assert response.headers["x-trace-id"] == incoming_trace_id
    assert response.headers["x-request-id"] == "custom-req-999"

    http_event = exporter.events[-1]
    assert http_event.trace.trace_id == incoming_trace_id
    assert http_event.trace.parent_span_id == incoming_parent_span
    assert http_event.trace.request_id == "custom-req-999"


def test_fastapi_exception_capture(recording_setup):
    client, exporter = recording_setup

    response = client.get("/error-endpoint")
    assert response.status_code == 500

    # At least the automatic error event should be recorded
    error_event = exporter.events[-1]
    assert error_event.event.type == "http_request"
    assert error_event.event.severity == "ERROR"
    assert error_event.http.status_code == 500
    assert error_event.error is not None
    assert error_event.error.type == "RuntimeError"
    assert "Database connection pool exhausted" in error_event.error.message
    assert "Traceback" in error_event.error.stacktrace


def test_fastapi_client_error_warning(recording_setup):
    client, exporter = recording_setup

    response = client.get("/client-error")
    assert response.status_code == 404

    http_event = exporter.events[-1]
    assert http_event.event.type == "http_request"
    assert http_event.event.severity == "WARNING"
    assert http_event.http.status_code == 404


# ==============================================================================
# EDGE CASES & BOUNDARY VALUES
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
    exporter = RecordingExporter()
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
    exporter = RecordingExporter()

    async def mock_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def dummy_receive():
        return {}

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
            (cast(Any, None), b"invalid-header-name"),
            (b"x-custom-header", cast(Any, 12345)),
        ]
    }

    asyncio.run(middleware(scope, dummy_receive, dummy_send))

    assert len(exporter.events) == 1
    ev = exporter.events[0]
    assert ev.http.user_agent == "PyTraceAgent"
    assert "x-custom-header" not in ev.http.headers if ev.http.headers else True


def test_fastapi_middleware_exception_and_error_handling():
    """Test PyTraceMiddleware catching, logging, and re-raising exceptions raised by the app."""
    exporter = RecordingExporter()

    async def failing_app(scope, receive, send):
        raise RuntimeError("Database connection timed out")

    async def dummy_receive():
        return {}

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
        asyncio.run(middleware(scope, dummy_receive, dummy_send))

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
    exporter = RecordingExporter()

    captured_messages = []
    async def mock_send(message):
        captured_messages.append(message)

    async def mock_app(scope, receive, send):
        # We don't specify "headers" key in the response message
        await send({"type": "http.response.start", "status": 201})

    async def dummy_receive():
        return {}

    middleware = PyTraceMiddleware(app=mock_app, exporter=exporter)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/no-headers",
        "headers": []
    }

    asyncio.run(middleware(scope, dummy_receive, mock_send))

    assert len(exporter.events) == 1
    assert exporter.events[0].http.status_code == 201

    # Check that headers were injected even though the original message had no headers
    assert len(captured_messages) == 1
    msg = captured_messages[0]
    headers_dict = dict(msg["headers"])
    assert b"x-request-id" in headers_dict
    assert b"x-trace-id" in headers_dict
    assert b"traceparent" in headers_dict
