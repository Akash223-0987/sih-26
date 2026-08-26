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
    assert get_current_trace_id() == "11112222333344445555666677778888"

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
    assert get_request_attributes() == {"tenant_id": "corp-10"}

    update_request_attribute("user_role", "admin")
    attrs = get_request_attributes()
    assert attrs["tenant_id"] == "corp-10"
    assert attrs["user_role"] == "admin"

    set_request_attributes({})  # reset
