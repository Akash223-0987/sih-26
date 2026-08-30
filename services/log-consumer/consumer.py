"""
consumer.py
===========
ULPF Kafka Consumer — the central processing stage of the pipeline.

Reads raw Fluent Bit records from the ``enterprise-logs`` Kafka topic,
delegates format-specific normalization to :mod:`normalizer`, and persists
the resulting canonical events to two complementary stores:

- **ClickHouse** — columnar, partition-compressed analytics store optimised
  for high-throughput time-series queries and SIEM dashboards.
- **Neo4j** — graph store that models IP-to-IP and IP-to-User relationships
  for threat-correlation, lateral-movement detection, and hunt queries.

Configuration constants
-----------------------
KAFKA_BROKER
    Bootstrap broker address for the Kafka cluster.
TOPIC_NAME
    Kafka topic that Fluent Bit publishes all log formats to.
BATCH_SIZE
    Maximum number of canonical records to buffer before a forced
    ClickHouse batch insert.  Larger batches improve write throughput on
    MergeTree engines at the cost of slightly higher memory usage.
BATCH_TIMEOUT_S
    Wall-clock seconds between time-based flushes.  Ensures low-latency
    delivery even when event volume is sparse.
PRUNE_INTERVAL
    Seconds between Neo4j graph pruning cycles.  Old relationships and
    orphan nodes are deleted to keep the graph size bounded.
"""

import json
import logging
import time
from confluent_kafka import Consumer, KafkaError

from normalizer import normalize
from database import DatabaseManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ulpf.consumer")

KAFKA_BROKER    = "kafka:9092"
TOPIC_NAME      = "enterprise-logs"
BATCH_SIZE      = 100
BATCH_TIMEOUT_S = 5.0
PRUNE_INTERVAL  = 3600


def main() -> None:
    """
    Start the consumer event loop.

    Connects to Kafka and enters a continuous poll loop.  Each iteration
    checks whether the time-based flush threshold has been exceeded before
    processing the next message, ensuring bounded latency independently of
    throughput.  A separate timer triggers periodic Neo4j graph pruning
    without requiring a dedicated background thread.

    The loop terminates gracefully on ``KeyboardInterrupt``, flushing any
    buffered records before closing the Kafka consumer and database connections.
    """
    logger.info(f"Connecting to Kafka broker at {KAFKA_BROKER} ...")

    conf = {
        "bootstrap.servers": KAFKA_BROKER,
        "group.id":          "ulpf-consumer-group",
        "auto.offset.reset": "earliest",
    }

    consumer = Consumer(conf)
    consumer.subscribe([TOPIC_NAME])
    logger.info(f"Subscribed to topic '{TOPIC_NAME}'. Waiting for messages...")

    db            = DatabaseManager()
    batch: list   = []
    last_flush_ts = time.monotonic()
    last_prune_ts = time.monotonic()

    try:
        while True:
            msg = consumer.poll(timeout=1.0)

            elapsed = time.monotonic() - last_flush_ts
            if batch and elapsed >= BATCH_TIMEOUT_S:
                _flush(db, batch)
                batch         = []
                last_flush_ts = time.monotonic()

            if time.monotonic() - last_prune_ts >= PRUNE_INTERVAL:
                db.prune_old_graph_data(retention_days=7)
                last_prune_ts = time.monotonic()

            if msg is None:
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                raw_record = json.loads(msg.value().decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                logger.warning(f"Skipping unparseable message: {exc}")
                continue

            try:
                canonical = normalize(raw_record)
            except Exception as exc:
                logger.error(f"Normalization failed: {exc}", exc_info=True)
                continue

            logger.debug(
                f"[{canonical.get('log_source')}] "
                f"{canonical.get('severity')} | "
                f"{canonical.get('src_ip')} -> {canonical.get('dest_ip')} | "
                f"{canonical.get('action')}"
            )

            batch.append(canonical)

            if len(batch) >= BATCH_SIZE:
                _flush(db, batch)
                batch         = []
                last_flush_ts = time.monotonic()

    except KeyboardInterrupt:
        logger.info("Shutting down — flushing remaining batch...")
        if batch:
            _flush(db, batch)
    finally:
        consumer.close()
        db.close()
        logger.info("Consumer stopped.")


def _flush(db: DatabaseManager, batch: list) -> None:
    """
    Persist a batch of canonical records to ClickHouse and Neo4j.

    Inserts all records as a single columnar batch into ClickHouse for
    optimal MergeTree write performance.  Subsequently iterates the batch
    and calls the Neo4j correlator for each record that carries network
    identifiers (source or destination IP), skipping pure application logs
    that have no network graph value.

    Parameters
    ----------
    db:
        Active :class:`database.DatabaseManager` instance.
    batch:
        List of canonical record dicts as returned by :func:`normalizer.normalize`.
    """
    logger.info(f"Flushing batch of {len(batch)} records to ClickHouse + Neo4j ...")
    db.insert_logs_batch(batch)
    for record in batch:
        if record.get("src_ip") or record.get("dest_ip"):
            db.correlate_in_neo4j(record)


if __name__ == "__main__":
    main()
