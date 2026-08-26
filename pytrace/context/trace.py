"""
PyTrace Trace Context Management.
Handles distributed trace ID and span ID propagation via ContextVar and W3C traceparent headers.
"""

from __future__ import annotations

import contextvars
import os
import secrets
from typing import Optional, Tuple, Union

_trace_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("pytrace_trace_id", default=None)
_span_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("pytrace_span_id", default=None)
_parent_span_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("pytrace_parent_span_id", default=None)


def generate_trace_id() -> str:
    """Generate a 32-character hexadecimal trace ID (128-bit UUID style)."""
    return secrets.token_hex(16)


def generate_span_id() -> str:
    """Generate a 16-character hexadecimal span ID (64-bit)."""
    return secrets.token_hex(8)


def get_current_trace_id() -> Optional[str]:
    """Retrieve current trace ID from context."""
    val = _trace_id_ctx.get()
    return str(val) if val is not None and not isinstance(val, contextvars.Token) else None


def set_current_trace_id(trace_id: Union[Optional[str], contextvars.Token]) -> contextvars.Token:
    """Set current trace ID in context (or reset if token provided)."""
    if isinstance(trace_id, contextvars.Token):
        _trace_id_ctx.reset(trace_id)
        return trace_id
    return _trace_id_ctx.set(trace_id)


def reset_trace_id(token: contextvars.Token) -> None:
    """Reset trace ID using token."""
    _trace_id_ctx.reset(token)


def get_current_span_id() -> Optional[str]:
    """Retrieve current span ID from context."""
    val = _span_id_ctx.get()
    return str(val) if val is not None and not isinstance(val, contextvars.Token) else None


def set_current_span_id(span_id: Union[Optional[str], contextvars.Token]) -> contextvars.Token:
    """Set current span ID in context (or reset if token provided)."""
    if isinstance(span_id, contextvars.Token):
        _span_id_ctx.reset(span_id)
        return span_id
    return _span_id_ctx.set(span_id)


def reset_span_id(token: contextvars.Token) -> None:
    """Reset span ID using token."""
    _span_id_ctx.reset(token)


def get_current_parent_span_id() -> Optional[str]:
    """Retrieve current parent span ID from context."""
    val = _parent_span_id_ctx.get()
    return str(val) if val is not None and not isinstance(val, contextvars.Token) else None


def set_current_parent_span_id(parent_span_id: Union[Optional[str], contextvars.Token]) -> contextvars.Token:
    """Set current parent span ID in context (or reset if token provided)."""
    if isinstance(parent_span_id, contextvars.Token):
        _parent_span_id_ctx.reset(parent_span_id)
        return parent_span_id
    return _parent_span_id_ctx.set(parent_span_id)


def reset_parent_span_id(token: contextvars.Token) -> None:
    """Reset parent span ID using token."""
    _parent_span_id_ctx.reset(token)


def parse_w3c_traceparent(traceparent: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a W3C traceparent header: 'version-trace_id-parent_id-trace_flags'.
    Example: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    Returns (trace_id, parent_span_id).
    """
    try:
        parts = traceparent.strip().split("-")
        if len(parts) >= 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
            return parts[1], parts[2]
    except Exception:
        pass
    return None, None


def format_w3c_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    """Format trace context as standard W3C traceparent header."""
    flags = "01" if sampled else "00"
    return f"00-{trace_id}-{span_id}-{flags}"
