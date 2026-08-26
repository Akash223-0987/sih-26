"""
PyTrace Request Context Management.
Handles request ID and request-scoped attributes via ContextVar.
"""

from __future__ import annotations

import contextvars
import secrets
from typing import Any, Dict, Optional, Union

_request_id_ctx: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("pytrace_request_id", default=None)
_request_attrs_ctx: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("pytrace_request_attrs", default={})


def generate_request_id(prefix: str = "req_") -> str:
    """Generate unique correlation request ID."""
    return f"{prefix}{secrets.token_hex(8)}"


def get_current_request_id() -> Optional[str]:
    """Retrieve current request ID from context."""
    val = _request_id_ctx.get()
    return str(val) if val is not None and not isinstance(val, contextvars.Token) else None


def set_current_request_id(request_id: Union[Optional[str], contextvars.Token]) -> contextvars.Token:
    """Set current request ID in context (or reset if token provided)."""
    if isinstance(request_id, contextvars.Token):
        _request_id_ctx.reset(request_id)
        return request_id
    return _request_id_ctx.set(request_id)


def reset_request_id(token: contextvars.Token) -> None:
    """Reset request ID using token."""
    _request_id_ctx.reset(token)


def get_request_attributes() -> Dict[str, Any]:
    """Retrieve current request-scoped attributes."""
    val = _request_attrs_ctx.get()
    if isinstance(val, dict):
        return val.copy()
    return {}


def set_request_attributes(attrs: Union[Dict[str, Any], contextvars.Token]) -> contextvars.Token:
    """Set request-scoped attributes (or reset if token provided)."""
    if isinstance(attrs, contextvars.Token):
        _request_attrs_ctx.reset(attrs)
        return attrs
    return _request_attrs_ctx.set(attrs.copy())


def reset_request_attributes(token: contextvars.Token) -> None:
    """Reset request attributes using token."""
    _request_attrs_ctx.reset(token)


def update_request_attribute(key: str, value: Any) -> None:
    """Add or update a single attribute in the request context."""
    current = get_request_attributes()
    current[key] = value
    _request_attrs_ctx.set(current)
