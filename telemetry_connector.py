from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class TelemetryAggregator:
    """Fetch and fuse tabular ClickHouse and graph Neo4j telemetry."""

    def __init__(self, clickhouse_client: Any = None, neo4j_driver: Any = None) -> None:
        self.clickhouse_client = clickhouse_client
        self.neo4j_driver = neo4j_driver

    def fetch_clickhouse(self, event_id: str) -> Dict[str, Any]:
        defaults = {"bytes_in": 0.0, "bytes_out": 0.0, "src_port": 0, "dst_port": 0, "protocol": "unknown", "auth_failures": 0.0, "auth_successes": 0.0}
        if self.clickhouse_client is None:
            return defaults
        try:
            result = self.clickhouse_client.query("SELECT * FROM logs_table WHERE event_id = {event_id:String} LIMIT 1", parameters={"event_id": event_id})
            row = result.named_results()[0] if getattr(result, "named_results", None) and result.named_results() else (result.result_rows[0] if result.result_rows else {})
            if not isinstance(row, dict):
                row = dict(zip(getattr(result, "column_names", []), row))
            return {key: row.get(key, value) for key, value in defaults.items()}
        except Exception:
            logger.exception("ClickHouse telemetry query failed for event_id=%s", event_id)
            return defaults

    def fetch_neo4j(self, entity_id: str) -> Dict[str, Any]:
        defaults = {"in_degree": 0.0, "avg_span_duration_ms": 0.0, "max_call_depth": 0.0, "error_flag": 0.0}
        if self.neo4j_driver is None:
            return defaults
        try:
            query = "MATCH (entity {entity_id: $entity_id}) OPTIONAL MATCH (entity)<-[incoming:COMMUNICATED_WITH]-() RETURN count(incoming) AS in_degree, coalesce(avg(incoming.span_duration_ms), 0) AS avg_span_duration_ms, coalesce(max(incoming.call_depth), 0) AS max_call_depth, coalesce(max(incoming.error_flag), 0) AS error_flag"
            with self.neo4j_driver.session() as session:
                record = session.run(query, entity_id=entity_id).single()
            return {key: (record[key] if record and record[key] is not None else value) for key, value in defaults.items()}
        except Exception:
            logger.exception("Neo4j telemetry query failed for entity_id=%s", entity_id)
            return defaults

    def aggregate(self, event_id: str, entity_id: Optional[str] = None) -> Dict[str, Any]:
        result = self.fetch_clickhouse(event_id)
        result.update(self.fetch_neo4j(entity_id or event_id))
        return result