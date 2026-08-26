from typing import Any, Dict

from pytrace.ml.models import InferenceResult, RoutedPayloads


def route_result(result: InferenceResult) -> RoutedPayloads:
    log = result.normalized
    return RoutedPayloads(
        clickhouse={
            "timestamp_epoch": log.timestamp.timestamp(),
            "raw_log_sha256": log.raw_log_sha256,
            "embedding": result.embedding,
            "anomaly_score": result.anomaly_score,
            "risk_score": result.risk_score,
            "threat_label": result.threat_label,
            "processing_ms": result.processing_ms,
        },
        neo4j={
            "src_ip": log.src_ip, "dst_ip": log.dst_ip,
            "relationship": "CONNECTS_TO" if log.src_ip and log.dst_ip else None,
            "properties": {"port": log.dst_port, "protocol": log.protocol, "raw_log_sha256": log.raw_log_sha256},
        },
        siem={
            "risk_score": result.risk_score,
            "anomaly": result.anomaly,
            "anomaly_score": result.anomaly_score,
            "confidence": result.threat_confidence,
            "threat_label": result.threat_label,
            "raw_log_sha256": log.raw_log_sha256,
        },
    )
