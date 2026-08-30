from __future__ import annotations

from typing import Any, Dict, List

from pytrace.ml.models import InferenceResult


class Neo4jAdapter:
    """Build idempotent Cypher statements and parameters for network events."""

    def transform(self, result: InferenceResult) -> List[Dict[str, Any]]:
        log = result.normalized
        statements: List[Dict[str, Any]] = []
        if log.src_ip and log.dst_ip:
            statements.append({
                "cypher": "MERGE (src:IP {address: $src}) MERGE (dst:IP {address: $dst}) "
                "MERGE (src)-[r:COMMUNICATED_WITH {port: $port, protocol: $protocol}]->(dst) "
                "SET r.bytes = $bytes, r.timestamp = $timestamp",
                "parameters": {"src": log.src_ip, "dst": log.dst_ip, "port": log.dst_port, "protocol": log.protocol, "bytes": log.unmapped_properties.get("bytes"), "timestamp": log.timestamp.isoformat()},
            })
        if result.threat_label != "Benign" or result.anomaly_score > 0:
            statements.append({
                "cypher": "MERGE (threat:Threat {name: $name, category: $category}) "
                "SET threat.last_seen = $timestamp "
                "WITH threat MERGE (event:IP {address: $src}) "
                "MERGE (event)-[r:TRIGGERED]->(threat) SET r.score = $score, r.confidence = $confidence",
                "parameters": {"name": result.threat_label, "category": result.predicted_label, "src": log.src_ip or "unknown", "score": result.risk_score, "confidence": result.threat_confidence, "timestamp": log.timestamp.isoformat()},
            })
        return statements
