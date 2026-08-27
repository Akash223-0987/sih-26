import json
import threading
from typing import Any, cast
import pytest
from pydantic import ValidationError
from pytrace.models.event import (
    ErrorDetails,
    EventDetails,
    HttpDetails,
    MetadataDetails,
    PyTraceEvent,
    TraceDetails,
    utc_now_iso,
)


def test_utc_now_iso():
    ts = utc_now_iso()
    assert isinstance(ts, str)
    assert "T" in ts


def test_pytrace_event_defaults():
    event = PyTraceEvent()
    assert event.service == "default-service"
    assert event.environment == "development"
    assert event.framework == "fastapi"
    assert event.event.type == "log"
    assert event.event.severity == "INFO"
    assert event.metadata.sdk_name == "pytrace"
    assert event.metadata.sdk_version == "0.1.0"
    assert event.metadata.pid > 0


def test_pytrace_event_serialization():
    event = PyTraceEvent(
        service="order-service",
        environment="production",
        event=EventDetails(type="http_request", action="completed", severity="INFO", message="GET /orders/1"),
        http=HttpDetails(method="GET", path="/orders/1", status_code=200, client_ip="10.0.0.1"),
        duration_ms=15.42,
        trace=TraceDetails(trace_id="abc1234567890abcdef1234567890abc", request_id="req_001"),
        attributes={"order_id": 1001, "amount": 499.99},
    )

    json_str = event.to_json()
    data = json.loads(json_str)

    assert data["service"] == "order-service"
    assert data["environment"] == "production"
    assert data["event"]["type"] == "http_request"
    assert data["http"]["method"] == "GET"
    assert data["http"]["status_code"] == 200
    assert data["duration_ms"] == 15.42
    assert data["trace"]["trace_id"] == "abc1234567890abcdef1234567890abc"
    assert data["attributes"]["order_id"] == 1001
    assert data["attributes"]["amount"] == 499.99


def test_pytrace_error_details():
    try:
        raise ValueError("Invalid configuration setting")
    except Exception as e:
        import traceback
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        err = ErrorDetails(type=type(e).__name__, message=str(e), stacktrace=tb)

    event = PyTraceEvent(
        event=EventDetails(type="exception", severity="ERROR", message="An error occurred"),
        error=err,
    )
    data = json.loads(event.to_json())
    assert data["error"]["type"] == "ValueError"
    assert "Invalid configuration setting" in data["error"]["message"]
    assert "Traceback" in data["error"]["stacktrace"]


# ==============================================================================
# EDGE CASES & BOUNDARY VALUES
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
        PyTraceEvent(duration_ms=cast(Any, "not-a-float"))

    # Missing fields
    with pytest.raises(ValidationError):
        # Message is missing from dictionary unpacking to trigger validation error
        ErrorDetails(**cast(Any, {"type": "ValueError"}))

    # Malformed data (non-serializable object inside dict attributes)
    non_serializable = threading.current_thread()
    event_malformed = PyTraceEvent(attributes={"thread": non_serializable})

    # Should raise error on JSON serialization due to the non-serializable object
    with pytest.raises(Exception):
        event_malformed.to_json()
