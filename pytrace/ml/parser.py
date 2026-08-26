import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from pytrace.ml.models import NormalizedLog

_IP = r"(?:\d{1,3}\.){3}\d{1,3}"
_PATTERNS = {
    "src_ip": re.compile(r"(?:src(?:_ip|ip)?|source(?:_ip|ip)?|client)[=: ]+([\d.]+)", re.I),
    "dst_ip": re.compile(r"(?:dst(?:_ip|ip)?|dest(?:ination)?(?:_ip|ip)?|server)[=: ]+([\d.]+)", re.I),
    "src_port": re.compile(r"(?:src_?port|sport)[=: ]+(\d{1,5})", re.I),
    "dst_port": re.compile(r"(?:dst_?port|dport|port)[=: ]+(\d{1,5})", re.I),
    "protocol": re.compile(r"(?:proto(?:col)?)[=: ]+([\w-]+)", re.I),
    "event_action": re.compile(r"(?:action|event_action|operation)[=: ]+([\w-]+)", re.I),
    "auth_status": re.compile(r"(?:auth(?:_status|entication)?|status)[=: ]+(success|failure|failed|successfully|denied|allow|allowed|blocked)", re.I),
    "vendor": re.compile(r"(?:vendor|product|device)[=: ]+([\w.-]+)", re.I),
}


def _first_ip(value: str, offset: int = 0) -> Optional[str]:
    matches = list(re.finditer(_IP, value))
    return matches[offset].group(0) if len(matches) > offset else None


def _timestamp(payload: Mapping[str, Any]) -> datetime:
    value = payload.get("timestamp") or payload.get("@timestamp")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def normalize_log(raw: Any) -> NormalizedLog:
    """Normalize structured or raw input while preserving the exact forensic source."""
    if isinstance(raw, str):
        raw_log = raw
        payload: Dict[str, Any] = {"message": raw}
    elif isinstance(raw, Mapping):
        payload = dict(raw)
        message = payload.get("message") or payload.get("log") or payload.get("raw_log")
        raw_log = message if isinstance(message, str) else str(raw)
    else:
        raw_log = str(raw)
        payload = {"message": raw_log}

    text = raw_log
    values: Dict[str, Any] = {}
    for key, pattern in _PATTERNS.items():
        match = pattern.search(text)
        if match:
            values[key] = match.group(1).lower() if key in {"protocol", "event_action", "auth_status"} else match.group(1)
    values.setdefault("src_ip", payload.get("src_ip") or payload.get("source.ip") or _first_ip(text))
    values.setdefault("dst_ip", payload.get("dst_ip") or payload.get("destination.ip") or _first_ip(text, 1))
    for key in ("src_port", "dst_port"):
        if values.get(key) is not None:
            values[key] = int(values[key])
        elif payload.get(key) is not None:
            values[key] = int(payload[key])
    for key in ("protocol", "event_action", "auth_status", "vendor"):
        values.setdefault(key, payload.get(key))
    known = set(values) | {"message", "log", "raw_log", "timestamp", "@timestamp"}
    attributes = {key: value for key, value in payload.items() if key not in known}
    return NormalizedLog(
        timestamp=_timestamp(payload), raw_log=raw_log,
        raw_log_sha256=hashlib.sha256(raw_log.encode("utf-8")).hexdigest(),
        attributes=attributes, unmapped_properties=attributes.copy(), **values,
    )
