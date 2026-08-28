"""
normalizer.py
=============
Universal Log Normalizer for the ULPF (Universal Log Pre-processing Framework).

Translates raw Fluent Bit records — regardless of origin format — into the
canonical schema consumed by ClickHouse (analytics store) and Neo4j
(threat-correlation graph).

Format dispatch is driven by the ``log_format`` field that Fluent Bit's
``record_modifier`` filter stamps onto every event.  A heuristic fallback
handles records that arrive without the field.

Supported formats
-----------------
json               : PyTrace SDK / any structured JSON application log
syslog_rfc5424     : RFC 5424 (modern firewalls, Linux rsyslog)
syslog_rfc3164     : RFC 3164 BSD syslog (Cisco, Juniper, legacy routers)
cef                : Common Event Format (Palo Alto, Fortinet, Check Point)
leef               : Log Event Extended Format (IBM QRadar)
apache_combined    : Apache / Nginx combined access log
windows_event_csv  : Windows Event Log exported via NXLog in CSV form
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _now_utc() -> datetime:
    """Return the current moment as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _parse_dt(value: Any) -> Optional[datetime]:
    """
    Parse *value* into a timezone-aware UTC datetime.

    Attempts the most common timestamp formats found across enterprise log
    sources in order of specificity.  Returns ``None`` when the value cannot
    be parsed, allowing callers to substitute a safe default.

    Parameters
    ----------
    value:
        Raw timestamp — may be a string, epoch int/float, or an existing
        datetime object.
    """
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    text = str(value).strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%b %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc, year=_now_utc().year)
            return dt
        except ValueError:
            continue
    return None


def _parse_cef_extensions(ext_str: str) -> Dict[str, str]:
    """
    Parse a CEF extension string into a key/value dictionary.

    CEF extensions use space-separated ``key=value`` pairs where values may
    themselves contain spaces.  The regex anchors on the next ``word=`` token
    to correctly delimit multi-word values.

    Parameters
    ----------
    ext_str:
        Raw CEF extension string, e.g.
        ``"src=10.0.0.1 dst=8.8.8.8 act=block app=web browsing"``.
    """
    result: Dict[str, str] = {}
    pattern = re.compile(r'(\w+)=((?:(?!\s\w+=).)+)')
    for match in pattern.finditer(ext_str):
        result[match.group(1).strip()] = match.group(2).strip()
    return result


def _parse_leef_attributes(attr_str: str) -> Dict[str, str]:
    """
    Parse a LEEF attribute string into a key/value dictionary.

    LEEF 2.0 separates key=value pairs with tab characters.

    Parameters
    ----------
    attr_str:
        Raw LEEF attribute string, e.g.
        ``"src=192.168.1.10\\tusrName=admin\\toutcome=success"``.
    """
    result: Dict[str, str] = {}
    for pair in attr_str.split("\t"):
        if "=" in pair:
            key, _, val = pair.partition("=")
            result[key.strip()] = val.strip()
    return result


def _syslog_pri_to_severity(pri: str) -> str:
    """
    Convert a numeric syslog PRI value to a severity label.

    The three least-significant bits of the PRI encode the severity per
    RFC 3164 / RFC 5424.

    Parameters
    ----------
    pri:
        String representation of the numeric PRI field.
    """
    mapping = {
        0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",
        3: "ERROR", 4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG",
    }
    try:
        return mapping.get(int(pri) & 0x7, "INFO")
    except (ValueError, TypeError):
        return "INFO"


def _http_status_to_severity(status_code: int) -> str:
    """
    Derive a severity label from an HTTP response status code.

    Parameters
    ----------
    status_code:
        Numeric HTTP status code.
    """
    if status_code >= 500:
        return "ERROR"
    if status_code >= 400:
        return "WARNING"
    return "INFO"


def _normalize_json(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a PyTrace canonical JSON event to the ULPF schema.

    PyTrace events are already structured; this function re-maps the nested
    fields to the flat ClickHouse column layout while preserving every
    original attribute in ``extra_attributes``.

    Parameters
    ----------
    raw:
        Parsed Fluent Bit record originating from a PyTrace JSON log line.
    """
    event = raw.get("event", {})
    http  = raw.get("http", {}) or {}
    trace = raw.get("trace", {}) or {}
    meta  = raw.get("metadata", {}) or {}

    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(raw.get("timestamp")) or _now_utc(),
        "log_source":       raw.get("service", "unknown"),
        "log_level":        event.get("severity", "INFO"),
        "severity":         event.get("severity", "INFO"),
        "src_ip":           http.get("client_ip", ""),
        "dest_ip":          "",
        "dest_port":        None,
        "user_name":        raw.get("attributes", {}).get("user_id", ""),
        "action":           event.get("action", ""),
        "protocol":         "HTTP" if http else "",
        "raw_message":      json.dumps(raw),
        "extra_attributes": {
            "framework":    raw.get("framework"),
            "environment":  raw.get("environment"),
            "trace_id":     trace.get("trace_id"),
            "request_id":   trace.get("request_id"),
            "span_id":      trace.get("span_id"),
            "http_method":  http.get("method"),
            "http_path":    http.get("path"),
            "status_code":  http.get("status_code"),
            "duration_ms":  raw.get("duration_ms"),
            "hostname":     meta.get("hostname"),
        },
    }


def _normalize_syslog_rfc5424(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a Syslog RFC 5424 event to the ULPF schema.

    RFC 5424 provides a structured PRI, version, timestamp, hostname,
    application name, process ID, message ID, structured data, and message.

    Parameters
    ----------
    raw:
        Fluent Bit record produced by the ``syslog_rfc5424`` regex parser.
    """
    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(raw.get("timestamp")) or _now_utc(),
        "log_source":       raw.get("app_name") or raw.get("hostname", "syslog"),
        "log_level":        _syslog_pri_to_severity(raw.get("pri", "14")),
        "severity":         _syslog_pri_to_severity(raw.get("pri", "14")),
        "src_ip":           "",
        "dest_ip":          "",
        "dest_port":        None,
        "user_name":        "",
        "action":           "",
        "protocol":         "syslog",
        "raw_message":      raw.get("message", ""),
        "extra_attributes": {
            "hostname":  raw.get("hostname"),
            "app_name":  raw.get("app_name"),
            "procid":    raw.get("procid"),
            "msgid":     raw.get("msgid"),
            "pri":       raw.get("pri"),
            "version":   raw.get("version"),
            "sd":        raw.get("sd"),
        },
    }


def _normalize_syslog_rfc3164(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a Syslog RFC 3164 (BSD syslog) event to the ULPF schema.

    IP address and authenticating username are extracted from the free-text
    message body using well-known sshd and PAM log patterns.

    Parameters
    ----------
    raw:
        Fluent Bit record produced by the ``syslog_rfc3164`` regex parser.
    """
    msg = raw.get("message", "")

    ip_match   = re.search(r'from\s+([\d\.]+)', msg)
    user_match = re.search(r'for\s+(\S+)\s+from', msg)

    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(raw.get("timestamp")) or _now_utc(),
        "log_source":       raw.get("hostname", "syslog3164"),
        "log_level":        _syslog_pri_to_severity(raw.get("pri", "14")),
        "severity":         _syslog_pri_to_severity(raw.get("pri", "14")),
        "src_ip":           ip_match.group(1) if ip_match else "",
        "dest_ip":          "",
        "dest_port":        None,
        "user_name":        user_match.group(1) if user_match else "",
        "action":           raw.get("app_name", ""),
        "protocol":         "syslog",
        "raw_message":      msg,
        "extra_attributes": {
            "hostname": raw.get("hostname"),
            "app_name": raw.get("app_name"),
            "procid":   raw.get("procid"),
            "pri":      raw.get("pri"),
        },
    }


def _normalize_cef(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a CEF (Common Event Format) event to the ULPF schema.

    CEF is used by Palo Alto Networks, Fortinet, Check Point, ArcSight, and
    Cisco ASA.  The numeric severity field (0–10) is mapped to a label.
    Extension keys ``src``/``c6a1`` and ``dst``/``c6a3`` handle both IPv4
    and IPv6 address representations.

    Parameters
    ----------
    raw:
        Fluent Bit record produced by the ``cef`` regex parser.
    """
    ext = _parse_cef_extensions(raw.get("extensions", ""))

    sev_raw = str(raw.get("severity", "5"))
    try:
        sev_int  = int(sev_raw)
        severity = (
            "CRITICAL" if sev_int >= 9 else
            "ERROR"    if sev_int >= 7 else
            "WARNING"  if sev_int >= 4 else
            "INFO"
        )
    except ValueError:
        severity = sev_raw.upper()

    try:
        dest_port = int(ext.get("dpt", 0)) or None
    except (ValueError, TypeError):
        dest_port = None

    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(ext.get("rt") or ext.get("start")) or _now_utc(),
        "log_source":       f"{raw.get('device_vendor', '')} {raw.get('device_product', '')}".strip(),
        "log_level":        severity,
        "severity":         severity,
        "src_ip":           ext.get("src", ext.get("c6a1", "")),
        "dest_ip":          ext.get("dst", ext.get("c6a3", "")),
        "dest_port":        dest_port,
        "user_name":        ext.get("suser", ext.get("user", "")),
        "action":           ext.get("act", raw.get("event_name", "")),
        "protocol":         ext.get("proto", ext.get("app", "")),
        "raw_message":      (
            f"CEF:{raw.get('cef_version')}|{raw.get('device_vendor')}|"
            f"{raw.get('device_product')}|{raw.get('device_version')}|"
            f"{raw.get('signature_id')}|{raw.get('event_name')}|"
            f"{raw.get('severity')}|{raw.get('extensions')}"
        ),
        "extra_attributes": {
            "cef_version":    raw.get("cef_version"),
            "device_vendor":  raw.get("device_vendor"),
            "device_product": raw.get("device_product"),
            "signature_id":   raw.get("signature_id"),
            "extensions":     ext,
        },
    }


def _normalize_leef(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a LEEF (Log Event Extended Format) event to the ULPF schema.

    LEEF is the native format of IBM QRadar SIEM.  Attribute pairs are
    tab-delimited.  Common field aliases (``src`` / ``srcIP``,
    ``usrName`` / ``username``) are resolved with priority to the shorter form.

    Parameters
    ----------
    raw:
        Fluent Bit record produced by the ``leef`` regex parser.
    """
    attrs = _parse_leef_attributes(raw.get("attributes", ""))

    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(attrs.get("devTime") or attrs.get("devTimeFormat")) or _now_utc(),
        "log_source":       f"{raw.get('vendor', '')} {raw.get('product', '')}".strip(),
        "log_level":        attrs.get("sev", "INFO").upper(),
        "severity":         attrs.get("sev", "INFO").upper(),
        "src_ip":           attrs.get("src", attrs.get("srcIP", "")),
        "dest_ip":          attrs.get("dst", attrs.get("dstIP", "")),
        "dest_port":        int(attrs["dstPort"]) if attrs.get("dstPort", "").isdigit() else None,
        "user_name":        attrs.get("usrName", attrs.get("username", "")),
        "action":           raw.get("event_id", ""),
        "protocol":         attrs.get("proto", ""),
        "raw_message":      (
            f"LEEF:{raw.get('leef_version')}|{raw.get('vendor')}|"
            f"{raw.get('product')}|{raw.get('product_version')}|"
            f"{raw.get('event_id')}|{raw.get('attributes')}"
        ),
        "extra_attributes": {
            "leef_version":    raw.get("leef_version"),
            "vendor":          raw.get("vendor"),
            "product":         raw.get("product"),
            "product_version": raw.get("product_version"),
            "attributes":      attrs,
        },
    }


def _normalize_apache_combined(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize an Apache / Nginx combined access log event to the ULPF schema.

    HTTP severity is derived from the response status code: 5xx maps to ERROR,
    4xx to WARNING, and all other codes to INFO.

    Parameters
    ----------
    raw:
        Fluent Bit record produced by the ``apache_combined`` regex parser.
    """
    try:
        status = int(raw.get("status_code", 200))
    except (ValueError, TypeError):
        status = 200

    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(raw.get("timestamp")) or _now_utc(),
        "log_source":       "webserver",
        "log_level":        _http_status_to_severity(status),
        "severity":         _http_status_to_severity(status),
        "src_ip":           raw.get("src_ip", ""),
        "dest_ip":          "",
        "dest_port":        80,
        "user_name":        raw.get("user_name", "-"),
        "action":           raw.get("http_method", ""),
        "protocol":         "HTTP",
        "raw_message":      (
            f'{raw.get("src_ip")} - {raw.get("user_name")} '
            f'[{raw.get("timestamp")}] '
            f'"{raw.get("http_method")} {raw.get("http_path")} {raw.get("http_version")}" '
            f'{raw.get("status_code")} {raw.get("bytes_sent")}'
        ),
        "extra_attributes": {
            "http_method":  raw.get("http_method"),
            "http_path":    raw.get("http_path"),
            "http_version": raw.get("http_version"),
            "status_code":  status,
            "bytes_sent":   raw.get("bytes_sent"),
            "referer":      raw.get("referer"),
            "user_agent":   raw.get("user_agent"),
        },
    }


def _normalize_windows_event_csv(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a Windows Event Log (NXLog CSV export) event to the ULPF schema.

    Security-relevant Event IDs — failed logons (4625), explicit credential
    use (4648), privilege escalation (4672), Kerberos activity (4768, 4769,
    4776), and audit log clearing (1102) — are elevated to WARNING severity.

    Parameters
    ----------
    raw:
        Fluent Bit record produced by the ``windows_event_csv`` regex parser.
    """
    event_id      = str(raw.get("event_id", ""))
    sensitive_ids = {"4625", "4648", "4672", "4768", "4769", "4776", "1102"}
    severity      = "WARNING" if event_id in sensitive_ids else "INFO"

    return {
        "event_id":         str(uuid.uuid4()),
        "timestamp":        _parse_dt(raw.get("timestamp")) or _now_utc(),
        "log_source":       raw.get("log_source", "Windows"),
        "log_level":        severity,
        "severity":         severity,
        "src_ip":           raw.get("src_ip", ""),
        "dest_ip":          "",
        "dest_port":        None,
        "user_name":        raw.get("user_name", ""),
        "action":           raw.get("action", ""),
        "protocol":         "",
        "raw_message":      (
            f'{raw.get("timestamp")},{raw.get("log_source")},'
            f'{raw.get("event_id")},{raw.get("user_name")},'
            f'{raw.get("hostname")},{raw.get("src_ip")},{raw.get("action")}'
        ),
        "extra_attributes": {
            "windows_event_id": event_id,
            "hostname":         raw.get("hostname"),
            "log_source":       raw.get("log_source"),
        },
    }


_NORMALIZERS = {
    "json":              _normalize_json,
    "syslog_rfc5424":    _normalize_syslog_rfc5424,
    "syslog_rfc3164":    _normalize_syslog_rfc3164,
    "cef":               _normalize_cef,
    "leef":              _normalize_leef,
    "apache_combined":   _normalize_apache_combined,
    "windows_event_csv": _normalize_windows_event_csv,
}


def normalize(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a raw Fluent Bit record to the ULPF canonical schema.

    The function selects the appropriate format-specific normalizer using the
    ``log_format`` field stamped by Fluent Bit.  When that field is absent, a
    heuristic inspection of the raw message body is used to determine the
    format before falling back to ``syslog_rfc3164`` as the safest default.

    The ``extra_attributes`` field is serialized to a JSON string so it can
    be stored directly in the ClickHouse ``String`` column without further
    transformation.

    Parameters
    ----------
    record:
        Raw dict decoded from a Kafka message.  May contain any combination
        of keys produced by Fluent Bit's regex or JSON parsers.

    Returns
    -------
    Dict[str, Any]
        Canonical record matching the ``ulpf.logs_normalized`` ClickHouse
        table schema.
    """
    log_format = record.get("log_format", "").strip()

    if not log_format:
        raw_msg = str(record.get("message", record.get("raw_message", "")))
        if raw_msg.startswith("CEF:"):
            log_format = "cef"
        elif raw_msg.startswith("LEEF:"):
            log_format = "leef"
        elif "timestamp" in record and "service" in record:
            log_format = "json"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", raw_msg):
            log_format = "apache_combined"
        else:
            log_format = "syslog_rfc3164"

    normalizer_fn = _NORMALIZERS.get(log_format, _normalize_syslog_rfc3164)
    canonical     = normalizer_fn(record)

    if isinstance(canonical.get("extra_attributes"), dict):
        canonical["extra_attributes"] = json.dumps(canonical["extra_attributes"])

    return canonical
