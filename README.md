# PyTrace

> **Universal Log Pre-processing Framework (ULPF) with Python SDK**
> *Ingest any log format. Normalize to a single schema. Feed every SIEM and analytics platform.*

---

## Overview

Modern enterprises generate logs in dozens of incompatible formats -- Syslog, CEF, LEEF, JSON, Apache access logs, Windows Event logs -- from hundreds of different vendors. Security teams waste enormous effort writing one-off parsers before data can reach a SIEM or ML pipeline.

**PyTrace / ULPF** solves this at both ends:

- **Source side** -- A lightweight Python SDK (`pytrace`) auto-instruments applications and emits structured, lossless JSON events with W3C distributed tracing context built in.
- **Log pipeline** -- Fluent Bit and Kafka ingest logs from perimeter devices and applications; the consumer normalizes them and persists them only to ClickHouse.
- **Telemetry pipeline** -- OpenTelemetry receives metrics and traces and persists their service/span/metric relationships only to Neo4j.
- **Detection pipeline** -- Both evidence streams are triaged by threat detection. Suspicious evidence invokes the ML API, and confirmed alerts reach the notification service.

The result is a vendor-agnostic, containerized, air-gap-ready pipeline capable of handling billions of events per day.

---

## Architecture

```
  +-------------------------------------------------------------------------+
  |                        LOG SOURCES  (Any Format)                        |
  |                                                                         |
  |  PyTrace SDK   Syslog RFC5424   Syslog RFC3164   CEF   LEEF   Apache   |
  |  (JSON)        (Linux / FW)     (Cisco/Juniper)         (QRadar)(Nginx) |
  +--------+--------------+--------------+------------+------+-------+-----+
           |              |              |            |      |       |
           v              v              v            v      v       v
  +-------------------------------------------------------------------------+
  |                    Fluent Bit  (Universal Collector)                    |
  |                                                                         |
  |  7 x [INPUT] tail blocks  ->  per-format regex/json parsers            |
  |  record_modifier stamps log_format field on every event                |
  |  all streams fan-in to a single Kafka topic via [OUTPUT] kafka          |
  +----------------------------------+--------------------------------------+
                                     |
                                     v
                            Kafka  (enterprise-logs topic)
                                     |
                                     v
  +-------------------------------------------------------------------------+
  |              ULPF Consumer  (normalizer.py + consumer.py)               |
  |                                                                         |
  |  log_format dispatch  ->  format-specific normalizer  ->  canonical dict |
  |  batched ClickHouse insert  +  Neo4j relationship creation              |
  +------------------------+------------------------+------------------------+
                           |                        |
              +------------v----------+  +----------v--------------+
              |      ClickHouse       |  |         Neo4j           |
              |  logs_normalized      |  |  IP --> IP              |
              |  alerts               |  |  IP --> User            |
              +-----------------------+  +-------------------------+
```

---

## Features

- **Universal Ingestion** -- 7 industry log formats supported out of the box: JSON, Syslog RFC 5424, Syslog RFC 3164, CEF, LEEF, Apache/Nginx combined, and Windows Event CSV.
- **Lossless Normalization** -- Every original log line is preserved verbatim in `raw_message`. No data is discarded during normalization.
- **Format Auto-Detection** -- When the `log_format` field is absent, the normalizer heuristically detects the format from message content.
- **Plug-and-Play SDK** -- One-line FastAPI/ASGI instrumentation via `PyTrace(app, ...)`. Captures HTTP lifecycle, latency, status codes, and distributed trace context automatically.
- **W3C Distributed Tracing** -- Parses and propagates `traceparent`, `X-Trace-ID`, and `X-Request-ID` across async context boundaries.
- **Explicit Structured Logging** -- `logger.info("msg", key=value)` binds the active `trace_id` and `request_id` automatically.
- **Forensic Exception Capture** -- Full stacktraces and error class hierarchies on unhandled exceptions.
- **Sensitive Data Masking** -- Authorization headers, cookies, and tokens are redacted before export.
- **Threat Correlation Graph** -- Neo4j models IP-to-IP and IP-to-User relationships from every normalized event for lateral movement detection and threat hunting.
- **Air-Gap Ready** -- Fully containerized; no external connectivity required after the initial image pull.

---

## Repository Structure

```
sih-26/
  pytrace/                      Python SDK (installable package)
    models/event.py             Canonical PyTraceEvent Pydantic schema
    logging/                    StructuredLogger API
    instrumentation/            FastAPI / ASGI auto-instrumentation middleware
    exporters/                  File, stdout, Fluent Bit TCP, HTTP exporters
    context/                    Async-safe trace and request context vars

  config/
    fluent-bit/
      fluent-bit.conf           7 INPUT blocks + record_modifier filters + Kafka OUTPUT
      parsers.conf              7 regex / json parser definitions

  services/
    log-generator/              Shell script emitting all 7 log formats continuously
    log-consumer/
      normalizer.py             Format dispatch + per-format canonical schema mapping
      consumer.py               Kafka consumer -> normalizer -> ClickHouse + Neo4j
      database.py               DatabaseManager (ClickHouse batch writes + Neo4j graph)
    ML-Analyzer/                Anomaly detection service (in progress)

  infra/
    docker-compose.yml          Full stack: Kafka, Fluent Bit, ClickHouse, Neo4j
    clickhouse/init-db.sql      logs_normalized + alerts table DDL with ZSTD codec and TTL
    neo4j/init-graph.cypher     Unique constraint schema initialization

  tests/                        Pytest suite for SDK components
  examples/                     FastAPI demo application
```

---

## Setup & Running

### Prerequisites

- Docker >= 24 and Docker Compose v2
- Python >= 3.11 (SDK development or running tests only)

---

### Option A -- Full Pipeline (Recommended)

Launches the complete stack: log generator, Fluent Bit, Kafka, ULPF consumer, ClickHouse, and Neo4j.

```bash
git clone https://github.com/Aryan-202/sih-26.git
cd sih-26
docker compose -f infra/docker-compose.yml up --build
```

Once running, the log generator emits all 7 log formats every 2 seconds. Fluent Bit collects and forwards them to Kafka. The ULPF consumer normalizes and writes to both databases.

**Exposed endpoints:**

| Service | Address |
| :--- | :--- |
| Kafka broker | `localhost:9092` |
| ClickHouse HTTP API | `http://localhost:8123` |
| Neo4j Browser | `http://localhost:7474` |
| Grafana Dashboard | `http://localhost:3000` *(requires Grafana overlay)* |

Default Neo4j credentials: `neo4j` / `password123`

**Verify data in ClickHouse:**

```sql
SELECT log_source, severity, count() AS events
FROM ulpf.logs_normalized
GROUP BY log_source, severity
ORDER BY events DESC;
```

**Query the threat graph in Neo4j:**

```cypher
MATCH (src:IP)-[r:CONNECTED_TO]->(dst:IP)
RETURN src.address, dst.address, r.protocol, r.timestamp
ORDER BY r.timestamp DESC
LIMIT 25;
```

---

### Dashboard (Grafana)

To add the Grafana security operations dashboard, launch the stack with the Grafana overlay:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml up --build
```

Open `http://localhost:3000` in your browser. Default credentials: `admin` / `admin`.

The **ULPF Security Operations** dashboard is pre-provisioned and will be set as the home dashboard. It includes panels for:
- Total events, active alerts, unique source IPs, and log format counts
- Log ingestion rate over time
- Severity and log source distribution (donut charts)
- Top 10 source IPs and top alerted IPs
- Alert timeline stacked by severity
- Recent alerts table with full details

All panels auto-refresh every 10 seconds and respect the dashboard time picker.

To run the full architecture stack **with** Grafana:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.architecture.yml -f infra/docker-compose.grafana.yml up --build
```

---

### Option B -- SDK Only

Install the PyTrace SDK into an existing Python project:

```bash
pip install git+https://github.com/Aryan-202/sih-26.git
```

Or in editable mode for local development:

```bash
git clone https://github.com/Aryan-202/sih-26.git
cd sih-26
pip install -e .
```

Instrument a FastAPI application:

```python
from fastapi import FastAPI
from pytrace import PyTrace, logger

app = FastAPI(title="Payment Service")

PyTrace(app, service_name="payment-service", environment="production")

@app.get("/users/{user_id}")
def get_user(user_id: int):
    logger.info("User profile requested", user_id=user_id, region="ap-south-1")
    return {"user_id": user_id, "status": "active"}
```

---

## Supported Log Formats

| Format | Parser | Typical Sources |
| :--- | :--- | :--- |
| Structured JSON | `json` | PyTrace SDK, cloud services, structured application logs |
| Syslog RFC 5424 | `syslog_rfc5424` | Linux rsyslog, modern next-gen firewalls |
| Syslog RFC 3164 | `syslog_rfc3164` | Cisco IOS, Juniper JunOS, legacy routers and switches |
| CEF | `cef` | Palo Alto PAN-OS, Fortinet FortiGate, Check Point, ArcSight |
| LEEF | `leef` | IBM QRadar SIEM |
| Apache / Nginx | `apache_combined` | Web server access logs |
| Windows Event CSV | `windows_event_csv` | Windows Security log via NXLog or winlogbeat |

Each format is processed by a dedicated Fluent Bit `[INPUT]` block with its own parser. A `record_modifier` filter stamps a `log_format` field on every event. The ULPF consumer reads this field to dispatch to the correct normalizer function without re-parsing.

---

## Canonical Schema

All formats are normalized to the following flat schema before storage in ClickHouse:

| Field | Type | Description |
| :--- | :--- | :--- |
| `event_id` | UUID | Unique identifier for this normalized event |
| `timestamp` | DateTime64(UTC) | Event time, always in UTC |
| `log_source` | String | Originating service, device, or hostname |
| `log_level` | String | DEBUG, INFO, WARNING, ERROR, or CRITICAL |
| `severity` | String | Semantic severity (same scale as `log_level`) |
| `src_ip` | String | Source IP address |
| `dest_ip` | String | Destination IP address |
| `dest_port` | UInt16 | Destination port |
| `user_name` | String | Authenticating or acting user identity |
| `action` | String | Observed action: HTTP verb, syslog tag, CEF act, Windows event name |
| `protocol` | String | Network or application protocol |
| `raw_message` | String | Complete original log line, guaranteed lossless |
| `extra_attributes` | JSON String | All format-specific fields not mapped above |

`raw_message` guarantees lossless preservation. `extra_attributes` carries every vendor-specific extension key so forensic queries can reach the original data without re-parsing raw logs.

---

## SDK Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `PYTRACE_SERVICE_NAME` | `default-service` | Service or application name |
| `PYTRACE_ENV` | `development` | production, staging, or development |
| `PYTRACE_EXPORTER` | `file,stdout` | Comma-separated exporters: file, stdout, console, fluentbit |
| `PYTRACE_LOG_DIR` | `logs` | Directory for the JSONL log file |
| `PYTRACE_LOG_FILE` | `application.log` | Log file name |
| `PYTRACE_LOG_LEVEL` | `INFO` | Minimum export severity |
| `PYTRACE_FLUENTBIT_HOST` | `127.0.0.1` | Fluent Bit TCP host |
| `PYTRACE_FLUENTBIT_PORT` | `24224` | Fluent Bit TCP port |
| `PYTRACE_CAPTURE_HEADERS` | `true` | Capture sanitized HTTP headers |

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

The test suite covers SDK configuration, distributed trace context propagation, all exporters, FastAPI auto-instrumentation middleware, and the `PyTraceEvent` Pydantic model.

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
