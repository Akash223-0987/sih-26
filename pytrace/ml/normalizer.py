"""Fast, offline semantic normalization for heterogeneous log fields."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any, Dict, Mapping, Optional, Tuple

STANDARD_FIELDS: Tuple[str, ...] = (
    "source.ip", "destination.ip", "source.port", "destination.port",
    "network.protocol", "user.name", "event.action", "event.outcome",
)

_ALIASES: Dict[str, Tuple[str, ...]] = {
    "source.ip": ("src_ip", "saddr", "source_ip", "client_ip", "srcaddress", "c_ip"),
    "destination.ip": ("dst_ip", "daddr", "destination_ip", "server_ip", "dstaddress"),
    "source.port": ("src_port", "sport", "source_port", "client_port"),
    "destination.port": ("dst_port", "dport", "destination_port", "dest_port"),
    "network.protocol": ("protocol", "proto", "transport", "network_protocol"),
    "user.name": ("user", "username", "user_name", "account", "principal"),
    "event.action": ("action", "event_action", "operation", "event_type"),
    "event.outcome": ("status", "auth_status", "outcome", "result"),
}
_TOKEN = re.compile(r"[a-z0-9]+")


def _tokens(value: str) -> set[str]:
    return set(_TOKEN.findall(value.casefold().replace(".", "_")))


def _embedding(value: str, dimensions: int = 32) -> list[float]:
    vector = [0.0] * dimensions
    for token in _tokens(value):
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        vector[int.from_bytes(digest[:4], "big") % dimensions] += 1.0 if digest[4] & 1 else -1.0
    norm = math.sqrt(sum(item * item for item in vector)) or 1.0
    return [item / norm for item in vector]


def _cosine(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _canonical_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.casefold())


_FAST_PATH = {
    _canonical_key(alias): field
    for field, aliases in _ALIASES.items()
    for alias in aliases
}


def normalize_fields(payload: Mapping[str, Any], minimum_similarity: float = 0.55) -> Dict[str, Any]:
    """Map vendor keys to ECS/OCSF-like fields without network or model downloads.

    Exact aliases take the constant-time fast path. Unknown keys use a small
    deterministic hashed embedding and cosine similarity against the alias index.
    Values that cannot be mapped remain available to the caller as unmapped data.
    """
    normalized: Dict[str, Any] = {}
    for key, value in payload.items():
        canonical = _canonical_key(str(key))
        field = _FAST_PATH.get(canonical)
        if field is None:
            key_vector = _embedding(str(key))
            candidates = (
                (candidate_field, alias)
                for candidate_field, aliases in _ALIASES.items()
                for alias in aliases
            )
            field, similarity = max(
                ((candidate_field, _cosine(key_vector, _embedding(alias))) for candidate_field, alias in candidates),
                key=lambda item: item[1],
            )
            if similarity < minimum_similarity:
                continue
        normalized.setdefault(field, value)
    return normalized


def normalize_value(payload: Mapping[str, Any], field: str) -> Optional[Any]:
    """Return one normalized field from a heterogeneous mapping."""
    return normalize_fields(payload).get(field)