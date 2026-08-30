# ULPF ML Service - Quick Start Guide

## 1. Environment Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Verify installation
python -c "import lightgbm, sklearn, joblib, fastapi, httpx; print('✓ All dependencies installed')"
```

## 2. Train the Threat Model (Offline)

### Option A: Use Synthetic Telemetry (No CSV Required)
```bash
python train_kaggle_model.py
```
Output: `models/threat_model.joblib` (284 KB, ~120 samples per class)

### Option B: Train on Your Dataset
```bash
python train_kaggle_model.py --csv /path/to/cic-ids.csv
```
Expected CSV columns:
- Numeric: `bytes_in`, `bytes_out`, `src_port`, `dst_port`, `auth_failures`, `auth_successes`, `in_degree`, `avg_span_duration_ms`, `max_call_depth`, `error_flag`
- Categorical: `protocol`
- Target: `threat_label` or `label` or `attack_cat`

## 3. Start the ML Inference Service

```bash
# Single-process (development)
python -m uvicorn ml_service:app --host 127.0.0.1 --port 8000

# Production (multiple workers)
python -m uvicorn ml_service:app --host 0.0.0.0 --port 8000 --workers 4
```

Expected output:
```
Uvicorn running on http://127.0.0.1:8000
Check health: http://127.0.0.1:8000/health
```

## 4. Test the API

### Health Check
```bash
curl -X GET http://localhost:8000/health
```
Response:
```json
{"status": "ok", "model_ready": true}
```

### Benign Request
```bash
curl -X POST http://localhost:8000/predict-threat \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "evt-benign-1",
    "protocol": "tcp",
    "bytes_in": 800,
    "bytes_out": 700,
    "src_port": 12345,
    "dst_port": 443
  }'
```
Expected response:
```json
{
  "event_id": "evt-benign-1",
  "threat_label": "Benign",
  "confidence_score": 0.85,
  "is_anomaly": false,
  "risk_level": "LOW",
  "probabilities": {
    "Benign": 0.85,
    "Brute Force": 0.05,
    "Lateral Movement": 0.05,
    "Exfiltration": 0.03,
    "Port Scan": 0.02
  }
}
```

### Malicious Request (Port Scan)
```bash
curl -X POST http://localhost:8000/predict-threat \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "evt-scan-1",
    "protocol": "udp",
    "bytes_in": 150,
    "bytes_out": 80,
    "src_port": 1024,
    "dst_port": 22,
    "in_degree": 25
  }'
```
Expected response:
```json
{
  "event_id": "evt-scan-1",
  "threat_label": "Port Scan",
  "confidence_score": 0.92,
  "is_anomaly": true,
  "risk_level": "CRITICAL",
  "probabilities": {
    "Benign": 0.01,
    "Brute Force": 0.02,
    "Lateral Movement": 0.03,
    "Exfiltration": 0.02,
    "Port Scan": 0.92
  }
}
```

## 5. Run the Test Suite

```bash
# Focused redesigned service tests
python -m pytest tests/test_redesigned_ml_service.py -v

# Full repository tests
python -m pytest -v

# Quick summary
python -m pytest -q
```

Expected output:
```
52 passed in 3.10s
```

## 6. Integrate with Threat Detection Service

```python
import asyncio
from threat_detector import ThreatDetectionService, NotificationDispatcher
from telemetry_connector import TelemetryAggregator

async def send_alert(alert: dict):
    """Custom alert handler (e.g., send to SIEM, Slack, PagerDuty)."""
    print(f"🚨 ALERT: {alert['event_id']} - {alert['prediction']['threat_label']}")
    # TODO: Implement your notification logic here

async def main():
    # Initialize services
    telemetry = TelemetryAggregator()  # Will use None for ClickHouse/Neo4j (fallback defaults)
    notifications = NotificationDispatcher(send_alert)
    detector = ThreatDetectionService(
        telemetry=telemetry,
        notifications=notifications,
        prediction_url="http://localhost:8000/predict-threat"
    )
    
    # Evaluate an event
    result = await detector.evaluate(event_id="evt-001", entity_id="entity-001")
    print(f"Prediction: {result}")

# Run the detector
asyncio.run(main())
```

## 7. Connect ClickHouse & Neo4j (Optional)

If you have live database clusters:

```python
import clickhouse_connect
from neo4j import GraphDatabase
from telemetry_connector import TelemetryAggregator

# Connect to ClickHouse
ch_client = clickhouse_connect.get_client(
    host="localhost",
    port=8123,
    username="default",
    password=""
)

# Connect to Neo4j
neo4j_driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "password123")
)

# Inject into aggregator
telemetry = TelemetryAggregator(
    clickhouse_client=ch_client,
    neo4j_driver=neo4j_driver
)

# Now queries will hit live stores instead of using defaults
result = telemetry.aggregate("event-id-123")
print(result)
```

## 8. Performance Benchmarking

```python
from time import perf_counter
import requests
import json

url = "http://localhost:8000/predict-threat"
payload = {"event_id": "bench-1", "protocol": "tcp", "bytes_out": 100}

# Warmup
requests.post(url, json=payload)

# Benchmark (10 requests)
times = []
for i in range(10):
    start = perf_counter()
    response = requests.post(url, json=payload)
    elapsed_ms = (perf_counter() - start) * 1000
    times.append(elapsed_ms)
    print(f"Request {i+1}: {elapsed_ms:.2f} ms")

print(f"\nAverage: {sum(times)/len(times):.2f} ms")
print(f"Min: {min(times):.2f} ms")
print(f"Max: {max(times):.2f} ms")
```

Expected output:
```
Request 1: 4.23 ms
Request 2: 3.87 ms
Request 3: 3.91 ms
...
Average: 3.95 ms
Min: 3.87 ms
Max: 4.31 ms
```

## 9. Common Issues & Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'lightgbm'"
**Solution:** Install dependencies
```bash
pip install lightgbm scikit-learn numpy pandas joblib
```

### Issue: "ImportError: cannot import name 'app' from ml_service"
**Solution:** Ensure you're in the repository root directory
```bash
cd c:\Users\krish\Downloads\sih-26
python -m uvicorn ml_service:app --port 8000
```

### Issue: "TypeError: Router.__init__() got an unexpected keyword argument 'on_startup'"
**Solution:** Fix FastAPI/Starlette version mismatch
```bash
pip install "starlette>=0.37.2,<0.49"
```

### Issue: 503 "threat model is not ready"
**Solution:** Check that `models/threat_model.joblib` exists
```bash
# If missing, regenerate it
python train_kaggle_model.py
```

### Issue: "ClickHouse telemetry query failed" (if using live database)
**Solution:** Verify ClickHouse connection parameters in telemetry_connector.py
- Check host/port (default: localhost:8123)
- Verify `logs_table` exists in database
- Confirm authentication credentials

### Issue: "Neo4j telemetry query failed" (if using live database)
**Solution:** Verify Neo4j connection parameters
- Check URI format (default: bolt://localhost:7687)
- Verify credentials (default: neo4j/password123)
- Confirm query syntax matches your schema

## 10. Architecture Diagram

```
┌─────────────────┐
│ Raw Log Events  │
└────────┬────────┘
         │
    ┌────▼────────────────────┐
    │ TelemetryAggregator      │
    │  (ClickHouse + Neo4j)    │
    └────┬────────────────────┘
         │
    ┌────▼──────────────────────────────┐
    │ ML Service (FastAPI)               │
    │ POST /predict-threat               │
    │ - LGBMClassifier                   │
    │ - 5-class probability output       │
    │ - Risk level: LOW|MEDIUM|CRITICAL  │
    │ Latency: <5ms                      │
    └────┬──────────────────────────────┘
         │
    ┌────▼──────────────────────────────┐
    │ ThreatDetectionService             │
    │ - Filter: is_anomaly && risk_level │
    │ - Dispatch alerts                  │
    └────┬──────────────────────────────┘
         │
    ┌────▼──────────────────────────────┐
    │ NotificationDispatcher             │
    │ - SIEM / Slack / PagerDuty / ...   │
    └────────────────────────────────────┘
```

---

## API Reference

### POST /predict-threat
**Content-Type:** `application/json`

**Request Body (TelemetryPayload):**
```
{
  "event_id": "string" (default: "unknown"),
  "entity_id": "string" (default: "unknown"),
  "bytes_in": float (default: 0.0),
  "bytes_out": float (default: 0.0),
  "src_port": int (default: 0),
  "dst_port": int (default: 0),
  "protocol": string (default: "unknown"),
  "auth_failures": float (default: 0.0),
  "auth_successes": float (default: 0.0),
  "in_degree": float (default: 0.0),
  "avg_span_duration_ms": float (default: 0.0),
  "max_call_depth": float (default: 0.0),
  "error_flag": float (default: 0.0)
}
```

**Response (ThreatPredictionResponse):**
```
{
  "event_id": "string",
  "threat_label": "string",
  "confidence_score": float [0.0, 1.0],
  "is_anomaly": boolean,
  "risk_level": "LOW" | "MEDIUM" | "CRITICAL",
  "probabilities": {
    "Benign": float,
    "Brute Force": float,
    "Lateral Movement": float,
    "Exfiltration": float,
    "Port Scan": float
  }
}
```

**Status Codes:**
- 200: Success
- 422: Invalid payload
- 503: Model not ready

---

## Support

For issues or questions, check:
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) – Architecture & design
- [DELIVERY_CHECKLIST.md](DELIVERY_CHECKLIST.md) – QA verification
- [tests/test_redesigned_ml_service.py](tests/test_redesigned_ml_service.py) – Test examples
