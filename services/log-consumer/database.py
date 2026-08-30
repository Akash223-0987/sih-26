"""ClickHouse-only persistence for the log ingestion branch.

Neo4j is reserved for the independent OpenTelemetry metrics-and-traces branch,
which keeps data lineage consistent with the project architecture.
"""

from __future__ import annotations

import json
import os

import clickhouse_connect

CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "ulpf")
CLICKHOUSE_USER = os.environ.get("CLICKHOUSE_USER", "default")
CLICKHOUSE_PASSWORD = os.environ.get("CLICKHOUSE_PASSWORD", "")


class DatabaseManager:
    """Batch-writes lossless normalised log records to ClickHouse."""

    def __init__(self) -> None:
        self.ch_client = None
        self.connect_database()

    def connect_database(self) -> None:
        if self.ch_client:
            return
        try:
            print(f"[Storage] Connecting to ClickHouse ({CLICKHOUSE_HOST}:{CLICKHOUSE_PORT})...")
            self.ch_client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
                username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
            )
            self.ch_client.database = CLICKHOUSE_DB
            print("[Storage] ClickHouse connection established.")
        except Exception as exc:
            print(f"[Storage] ClickHouse connection failed: {exc}")

    def insert_logs_batch(self, logs_list: list[dict]) -> None:
        if not self.ch_client:
            self.connect_database()
        if not logs_list or not self.ch_client:
            return
        rows = [
            [
                log.get("event_id"), log.get("timestamp"), log.get("log_source", "unknown"),
                log.get("log_level", "INFO"), log.get("severity", "MEDIUM"), log.get("src_ip", ""),
                log.get("dest_ip", ""), log.get("dest_port"), log.get("user_name", ""),
                log.get("action", ""), log.get("protocol", ""), log.get("raw_message", ""),
                json.dumps(log.get("extra_attributes", {})),
            ]
            for log in logs_list
        ]
        try:
            self.ch_client.insert(
                table="logs_normalized", data=rows,
                column_names=[
                    "event_id", "timestamp", "log_source", "log_level", "severity", "src_ip",
                    "dest_ip", "dest_port", "user_name", "action", "protocol", "raw_message",
                    "extra_attributes",
                ],
                database=CLICKHOUSE_DB,
            )
            print(f"[Storage] Batch-inserted {len(logs_list)} records into ClickHouse.")
        except Exception as exc:
            print(f"[Storage] ClickHouse batch insertion failed: {exc}")

    def close(self) -> None:
        self.ch_client = None
