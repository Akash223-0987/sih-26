# ULPF Database Architecture & Optimization Documentation

This document describes the high-performance database setup for the **Universal Log Pre-processing Framework (ULPF)**, including schema optimizations, storage compression, and graph node constraints.

---

## 1. Database Storage Engines

### ClickHouse (OLAP Storage Engine)
ClickHouse acts as the high-volume log storage engine. It is optimized for sub-second analytical queries and high ingestion throughput.
* **Database name**: `ulpf`
* **Table for Logs**: `ulpf.logs_normalized` (stores structured events)
* **Table for Alerts**: `ulpf.alerts` (stores security correlation outputs)

### Neo4j (Graph Relationship Engine)
Neo4j stores key entities (IPs, Users, Alerts) and their interconnections to enable attack-path mapping and threat forensics.
* **Auth**: `neo4j/password123` (port `7687` Bolt, `7474` HTTP console)

---

## 2. ClickHouse Optimizations

The tables are configured in [init-db.sql](clickhouse/init-db.sql) with the following database-level performance optimizations:

### Column-Level Codec Compression
* **Codec**: `ZSTD(3)` is applied to `raw_message` and `extra_attributes` strings. This offers a high compression ratio (~10x reduction on typical server/network log payloads) with low CPU usage during decompression.

### Low Cardinality Mappings
* **LowCardinality(String)**: Applied to fields that have highly repetitive value sets:
  * `log_source` (e.g., `nginx`, `ssh`, `cisco`)
  * `log_level` (e.g., `INFO`, `ERROR`, `WARNING`)
  * `severity` (e.g., `LOW`, `HIGH`)
  * `action` (e.g., `login`, `web_request`)
  * `protocol` (e.g., `HTTP`, `SSH`, `TCP`)
  * This stores values as integers internally via a dictionary mapping, drastically reducing RAM overhead.

### Partitioning & TTL (7-Day Retention)
* **Partitioning**: Partitioned physically by day using `PARTITION BY toYYYYMMDD(timestamp)`.
* **Pruning Policy**: Configured using table-level TTL:
  ```sql
  TTL toDateTime(timestamp) + INTERVAL 7 DAY DELETE;
  ```
  ClickHouse automatically drops partitions older than 7 days in the background, preventing storage bloat.

---

## 3. Neo4j Graph Optimizations

The graph constraints are defined in [init-graph.cypher](neo4j/init-graph.cypher).

### Node Uniqueness Constraints
* To optimize graph size and prevent duplicate node entities, unique constraints are applied:
  - `CREATE CONSTRAINT unique_ip FOR (i:IP) REQUIRE i.address IS UNIQUE;`
  - `CREATE CONSTRAINT unique_user FOR (u:User) REQUIRE u.username IS UNIQUE;`
  - `CREATE CONSTRAINT unique_alert FOR (a:Alert) REQUIRE a.id IS UNIQUE;`
* This guarantees that when mapping relationships (e.g., `IP -> User`), Neo4j links to existing unique entity nodes rather than leaking memory with duplicate node versions.

---

## 4. Python Database Manager Interface (`database.py`)

A centralized database client is available at `services/log-consumer/database.py`. It implements:
1. **Connection Resilience**: Attempt-and-wait loop for robust container start synchronization.
2. **Columnar Batch Insertion**: `insert_logs_batch(logs)` for ClickHouse stream writing.
3. **Graph Correlation Queries**: Cypher code to automatically update `CONNECTED_TO` and `AUTHENTICATED` relationships.
4. **Neo4j Retention Pruning**: `prune_old_graph_data(retention_days)` to clean up old relationships and delete orphaned nodes (with 0 degrees) to keep graph footprint low.

---

## 5. Startup & Automated Provisioning

The database setup is completely hands-free. Running:
```bash
docker compose -f infra/docker-compose.yml up -d
```
Will automatically spin up the databases, run the SQL initialization script inside ClickHouse, wait for Neo4j to be healthy, and inject the Cypher constraints.
