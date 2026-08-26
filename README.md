# PyTrace 🚀

> **Developer Observability & Structured Telemetry Framework for Python**
> *Universal, lossless, and high-performance application telemetry designed for modern enterprise log pipelines.*

---

## 📖 Overview

Traditional enterprise observability often requires DevOps teams to write complex log scrapers and custom parser regexes for every application. **PyTrace** flips this model:

Instead of manual log scraping, developers install a **lightweight, plug-and-play Python SDK** into their applications. PyTrace **automatically instruments** HTTP lifecycles, latencies, and exceptions while offering an intuitive **explicit structured logging API** with built-in W3C distributed tracing context.

PyTrace emits standardized, lossless JSON events designed to feed seamlessly into **Fluent Bit**, **Kafka**, and downstream **Universal Log Pre-processing Frameworks (ULPF)**, SIEMs, and ML anomaly detectors.

---

## 🏛️ Architecture

```text
                 ENTERPRISE APPLICATION
                 ┌────────────────────────────────┐
                 │          FastAPI / ASGI        │
                 │                                │
                 │  @app.get("/api/users/{id}")   │
                 │                │               │
                 │                ▼               │
                 │          pytrace SDK           │
                 │   (Auto-Metrics + Logger API)  │
                 └────────────────┬───────────────┘
                                  │
                                  │ JSON Lines (lossless, structured)
                                  ▼
                 ┌────────────────────────────────┐
                 │          Fluent Bit            │
                 │                                │
                 │  - Reliable tail / socket      │
                 │  - Backpressure & buffer       │
                 │  - Resilient forwarding        │
                 └────────────────┬───────────────┘
                                  │
                                  ▼
                                Kafka
                                  │
          ┌───────────────────────┼───────────────────────┐
          ▼                       ▼                       ▼
     Data Lake / S3        Security / SIEM          ML & Anomaly
```

---

## ✨ Features

- **⚡ 1-Line Automatic Instrumentation**: Auto-capture HTTP request/response metrics, latencies (`duration_ms`), status codes, routes, and query parameters without modifying existing endpoint logic.
- **🔍 Distributed Tracing & W3C Propagation**: Automatically parses and propagates `traceparent`, `X-Trace-ID`, and `X-Request-ID` across async context boundaries.
- **📝 Explicit Structured Logging API**: `logger.info("message", key=value)` automatically attaches the current active `trace_id`, `request_id`, and host metadata.
- **🛡️ Forensic Error & Exception Capture**: Captures full stacktraces and error hierarchies for uncaught exceptions.
- **🔒 Sensitive Data Masking**: Automatically redacts authorization headers, cookies, and tokens.
- **🔌 Multi-Target Exporters**: Supports high-speed local JSONL files (for Fluent Bit `tail`), stdout, TCP socket streaming, and HTTP forwarders.
- **🔄 Standard Library Interop**: Drop-in `PyTraceHandler` to route existing `logging.getLogger()` calls directly into PyTrace.

---

## 🚀 Quick Start

### 1. Installation

```bash
pip install pytrace
```

Or install in editable mode for development:

```bash
git clone https://github.com/Aryan-202/sih-26.git
cd sih-26
pip install -e .
```

---

### 2. Automatic FastAPI Instrumentation

```python
from fastapi import FastAPI
from pytrace import PyTrace, logger

app = FastAPI(title="Payment Service")

# Initialize PyTrace with one line
PyTrace(app, service_name="payment-service", environment="production")

@app.get("/users/{user_id}")
def get_user(user_id: int):
    # Optional: Log business events correlated with the request trace
    logger.info(
        "User profile requested",
        user_id=user_id,
        region="ap-south-1"
    )
    return {"user_id": user_id, "status": "active"}
```

---

## 📊 Standardized Event Schema

Every event emitted by PyTrace conforms to the universal canonical schema:

```json
{
  "timestamp": "2026-08-26T15:05:21.123456Z",
  "service": "payment-service",
  "environment": "production",
  "framework": "fastapi",
  "event": {
    "type": "http_request",
    "action": "completed",
    "severity": "INFO",
    "message": "GET /users/123 completed with 200 in 12.4ms"
  },
  "http": {
    "method": "GET",
    "path": "/users/123",
    "route": "/users/{user_id}",
    "status_code": 200,
    "client_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0 ...",
    "query_params": {}
  },
  "duration_ms": 12.4,
  "trace": {
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id": "00f067aa0ba902b7",
    "parent_span_id": null,
    "request_id": "req_8f1b4a92c3d4"
  },
  "attributes": {
    "user_id": 123,
    "region": "ap-south-1"
  },
  "metadata": {
    "hostname": "prod-node-04",
    "pid": 2841,
    "thread_id": 140223,
    "sdk_name": "pytrace",
    "sdk_version": "0.1.0"
  }
}
```

---

## ⚙️ Configuration

PyTrace can be configured programmatically or via environment variables:

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `PYTRACE_SERVICE_NAME` | `default-service` | Name of the microservice / application |
| `PYTRACE_ENV` | `development` | Environment (`production`, `staging`, `development`) |
| `PYTRACE_EXPORTER` | `file,stdout` | Comma-separated exporters: `file`, `stdout`, `console`, `fluentbit` |
| `PYTRACE_LOG_DIR` | `logs` | Directory where `application.log` is written |
| `PYTRACE_LOG_FILE` | `application.log` | Target log file name |
| `PYTRACE_LOG_LEVEL` | `INFO` | Minimum severity to export (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |
| `PYTRACE_FLUENTBIT_HOST`| `127.0.0.1` | Fluent Bit TCP host |
| `PYTRACE_FLUENTBIT_PORT`| `24224` | Fluent Bit TCP port |
| `PYTRACE_CAPTURE_HEADERS`| `true` | Whether to capture sanitized HTTP headers |

---

## 🧪 Testing & Demo

Run the interactive demo application:

```bash
python examples/fastapi_demo.py
```

Run test suite:

```bash
pytest -v
```

---

## 🐳 Docker & Fluent Bit Pipeline

Launch the Fluent Bit collection service and sample log producer:

```bash
docker-compose -f infra/docker-compose.yml up --build
```

---

## 📄 License

Apache-2.0. See [LICENSE](LICENSE) for details.
