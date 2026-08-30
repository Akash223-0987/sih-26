import contextvars
from typing import Any, cast
import pytest
from pytrace.context.request import (
    generate_request_id,
    get_current_request_id,
    get_request_attributes,
    set_current_request_id,
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
    reset_span_id,
    reset_parent_span_id,
    set_current_parent_span_id,
    set_current_span_id,
    set_current_trace_id,
)


def test_trace_id_generation():
    tid = generate_trace_id()
    assert len(tid) == 32
    assert isinstance(tid, str)


def test_span_id_generation():
    sid = generate_span_id()
    assert len(sid) == 16
    assert isinstance(sid, str)


def test_request_id_generation():
    rid = generate_request_id(prefix="req_test_")
    assert rid.startswith("req_test_")
    assert len(rid) > 10


def test_trace_context_propagation():
    assert get_current_trace_id() is None

    t1 = set_current_trace_id("11112222333344445555666677778888")
    try:
        assert get_current_trace_id() == "11112222333344445555666677778888"
    finally:
        set_current_trace_id(t1)  # reset


def test_w3c_traceparent_parse_and_format():
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    span_id = "00f067aa0ba902b7"

    header = format_w3c_traceparent(trace_id, span_id, sampled=True)
    assert header == f"00-{trace_id}-{span_id}-01"

    parsed_trace, parsed_parent = parse_w3c_traceparent(header)
    assert parsed_trace == trace_id
    assert parsed_parent == span_id


def test_request_attributes():
    token = set_request_attributes({"tenant_id": "corp-10"})
    try:
        assert get_request_attributes() == {"tenant_id": "corp-10"}

        update_request_attribute("user_role", "admin")
        attrs = get_request_attributes()
        assert attrs["tenant_id"] == "corp-10"
        assert attrs["user_role"] == "admin"
    finally:
        set_request_attributes(token)  # reset using the token



# ==============================================================================
# EDGE CASES & BOUNDARY VALUES
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
    reset_span_id(token_span)

    token_parent = set_current_parent_span_id(None)
    assert get_current_parent_span_id() is None
    reset_parent_span_id(token_parent)

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
    parsed_trace, parsed_parent = parse_w3c_traceparent(cast(Any, None))
    assert parsed_trace is None
    assert parsed_parent is None

    # Invalid inputs and data types
    parsed_trace, parsed_parent = parse_w3c_traceparent(cast(Any, 12345))
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
        set_request_attributes(cast(Any, None))

    with pytest.raises(AttributeError):
        set_request_attributes(cast(Any, "not-a-dict"))

    # Reset
    set_request_attributes(token)
