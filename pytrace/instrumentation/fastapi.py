"""
PyTrace FastAPI & ASGI Auto-Instrumentation Middleware.
Automatically captures HTTP requests, responses, latency, trace context, status codes, and exceptions.
"""

from __future__ import annotations

import sys
import time
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

from pytrace.config import PyTraceConfig, get_config
from pytrace.context.request import (
    generate_request_id,
    get_request_attributes,
    set_current_request_id,
    set_request_attributes,
)
from pytrace.context.trace import (
    format_w3c_traceparent,
    generate_span_id,
    generate_trace_id,
    parse_w3c_traceparent,
    set_current_parent_span_id,
    set_current_span_id,
    set_current_trace_id,
)
from pytrace.exporters.base import BaseExporter
from pytrace.exporters.composite import create_exporter_from_config
from pytrace.instrumentation.base import BaseInstrumentor
from pytrace.models.event import (
    ErrorDetails,
    EventDetails,
    HttpDetails,
    MetadataDetails,
    PyTraceEvent,
    TraceDetails,
)


def _decode_headers(raw_headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    """Convert ASGI byte-headers into a lowercase string dictionary."""
    headers: Dict[str, str] = {}
    for name, value in raw_headers:
        try:
            k = name.decode("latin1").lower()
            v = value.decode("latin1")
            headers[k] = v
        except Exception:
            continue
    return headers


def _filter_headers(headers: Dict[str, str], mask_keys: List[str]) -> Dict[str, str]:
    """Mask sensitive HTTP headers like Authorization or Cookies."""
    safe: Dict[str, str] = {}
    mask_set = {k.lower() for k in mask_keys}
    for k, v in headers.items():
        if k in mask_set:
            safe[k] = "[REDACTED]"
        else:
            safe[k] = v
    return safe


class PyTraceMiddleware:
    """
    High-performance ASGI middleware capturing HTTP transactions and propagating trace context.
    """

    def __init__(
        self,
        app: Any,
        config: Optional[PyTraceConfig] = None,
        exporter: Optional[BaseExporter] = None,
    ):
        self.app = app
        self.config = config or get_config()
        self.exporter = exporter or create_exporter_from_config(self.config)

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        headers = _decode_headers(raw_headers)

        # Trace context resolution
        trace_id = None
        parent_span_id = None

        traceparent = headers.get("traceparent")
        if traceparent:
            parsed_trace, parsed_parent = parse_w3c_traceparent(traceparent)
            if parsed_trace:
                trace_id = parsed_trace
                parent_span_id = parsed_parent

        if not trace_id:
            trace_id = headers.get("x-trace-id") or generate_trace_id()

        span_id = generate_span_id()
        request_id = headers.get("x-request-id") or generate_request_id()

        # Set context variables
        token_trace = set_current_trace_id(trace_id)
        token_span = set_current_span_id(span_id)
        token_parent_span = set_current_parent_span_id(parent_span_id)
        token_req = set_current_request_id(request_id)
        token_attrs = set_request_attributes({})

        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode("latin1")
        client = scope.get("client")
        client_ip = client[0] if client and len(client) > 0 else "127.0.0.1"
        user_agent = headers.get("user-agent")

        query_params: Optional[Dict[str, Any]] = None
        if self.config.capture_query_params and query_string:
            try:
                parsed_q = parse_qs(query_string)
                # Flatten single-item lists for clean JSON representation
                query_params = {k: v[0] if len(v) == 1 else v for k, v in parsed_q.items()}
            except Exception:
                pass

        captured_headers = _filter_headers(headers, self.config.mask_headers) if self.config.capture_headers else None

        status_code: Optional[int] = None
        error_details: Optional[ErrorDetails] = None
        start_time = time.perf_counter()

        async def send_wrapper(message: Dict[str, Any]) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)

                # Inject correlation headers to outgoing HTTP response
                if self.config.include_response_headers:
                    res_headers = list(message.get("headers", []))
                    res_headers.append((b"x-request-id", request_id.encode("latin1")))
                    res_headers.append((b"x-trace-id", trace_id.encode("latin1")))
                    res_headers.append((b"traceparent", format_w3c_traceparent(trace_id, span_id).encode("latin1")))
                    message["headers"] = res_headers

            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            err_type = type(exc).__name__
            err_msg = str(exc)
            err_tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            error_details = ErrorDetails(type=err_type, message=err_msg, stacktrace=err_tb)
            status_code = status_code or 500
            raise exc
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            actual_status = status_code if status_code is not None else 500

            # Determine severity
            if error_details or actual_status >= 500:
                severity = "ERROR"
                action = "failed"
            elif actual_status >= 400:
                severity = "WARNING"
                action = "client_error"
            else:
                severity = "INFO"
                action = "completed"

            msg = f"{method} {path} completed with {actual_status} in {duration_ms:.2f}ms"
            if error_details:
                msg = f"{method} {path} failed with {error_details.type}: {error_details.message}"

            http_info = HttpDetails(
                method=method,
                path=path,
                status_code=actual_status,
                client_ip=client_ip,
                user_agent=user_agent,
                query_params=query_params,
                headers=captured_headers,
            )

            trace_info = TraceDetails(
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
                    type="http_request",
                    action=action,
                    severity=severity,
                    message=msg,
                ),
                http=http_info,
                duration_ms=round(duration_ms, 3),
                trace=trace_info,
                attributes=get_request_attributes(),
                error=error_details,
                metadata=MetadataDetails(),
            )

            try:
                self.exporter.export(event)
            except Exception:
                pass

            # Reset context
            set_current_trace_id(token_trace)
            set_current_span_id(token_span)
            set_current_parent_span_id(token_parent_span)
            set_current_request_id(token_req)
            set_request_attributes(token_attrs)


class PyTrace(BaseInstrumentor):
    """
    Main PyTrace SDK instrumentor.
    Usage:
        from pytrace import PyTrace
        app = FastAPI()
        PyTrace(app)
    """

    def __init__(
        self,
        app: Optional[Any] = None,
        config: Optional[PyTraceConfig] = None,
        exporter: Optional[BaseExporter] = None,
        service_name: Optional[str] = None,
        environment: Optional[str] = None,
    ):
        self.config = config or get_config()
        if service_name:
            self.config.service_name = service_name
        if environment:
            self.config.environment = environment

        self.exporter = exporter or create_exporter_from_config(self.config)

        if app is not None:
            self.instrument(app)

    def instrument(self, app: Any) -> None:
        """Add PyTraceMiddleware to FastAPI / Starlette application."""
        app.add_middleware(PyTraceMiddleware, config=self.config, exporter=self.exporter)
