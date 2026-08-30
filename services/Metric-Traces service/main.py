import os
import json
import datetime
from typing import Dict, List, Any
from fastapi import FastAPI, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
from neo4j import GraphDatabase

# Graph database configuration. Metrics and traces never enter ClickHouse.
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "password123")
THREAT_DETECTION_URL = os.environ.get("THREAT_DETECTION_URL", "").strip()

app = FastAPI(title="ULPF OpenTelemetry Metrics & Traces Ingestor")

# Global counters, anomalies, and latest metrics cache per device
stats = {
    "metrics_received": 0,
    "traces_received": 0,
    "anomalies_detected": 0,
    "last_ingest_time": "N/A"
}
anomalies: List[Dict[str, Any]] = []
latest_device_metrics: Dict[str, Dict[str, Any]] = {}

def get_neo4j_driver():
    """Return an optional graph connection; telemetry ingestion must not block on it."""
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        print("[Telemetry Ingestor] Connected to Neo4j")
        return driver
    except Exception as exc:
        print(f"[Telemetry Ingestor] Neo4j unavailable: {exc}")
        return None


neo4j_driver = get_neo4j_driver()


def store_telemetry_graph(traces_rows, metrics_rows) -> None:
    """Preserve service-to-span and service-to-metric relationships for correlation."""
    if not neo4j_driver:
        return
    try:
        with neo4j_driver.session() as session:
            for row in traces_rows:
                timestamp, trace_id, span_id, parent_span_id, service_name, span_name, _, duration_ms, status_code, _, _ = row
                session.run(
                    "MERGE (s:Service {name: $service}) "
                    "MERGE (t:Trace {trace_id: $trace_id, span_id: $span_id}) "
                    "SET t.name=$name, t.timestamp=$timestamp, t.duration_ms=$duration_ms, t.status=$status "
                    "MERGE (s)-[:EMITTED]->(t)",
                    service=service_name, trace_id=trace_id, span_id=span_id, name=span_name,
                    timestamp=timestamp.isoformat(), duration_ms=duration_ms, status=status_code,
                )
                if parent_span_id:
                    session.run(
                        "MATCH (child:Trace {trace_id: $trace_id, span_id: $span_id}) "
                        "MERGE (parent:Trace {trace_id: $trace_id, span_id: $parent_span_id}) "
                        "MERGE (parent)-[:PARENT_OF]->(child)",
                        trace_id=trace_id, span_id=span_id, parent_span_id=parent_span_id,
                    )
            for row in metrics_rows:
                timestamp, metric_name, _, value, unit, attributes = row
                attributes_dict = json.loads(attributes)
                service_name = attributes_dict.get("service.name", "unknown_service")
                session.run(
                    "MERGE (s:Service {name: $service}) "
                    "CREATE (m:Metric {name:$name, value:$value, unit:$unit, timestamp:$timestamp}) "
                    "MERGE (s)-[:REPORTED]->(m)",
                    service=service_name, name=metric_name, value=value, unit=unit, timestamp=timestamp.isoformat(),
                )
    except Exception as exc:
        print(f"[Telemetry Ingestor] Neo4j graph write failed: {exc}")


async def fan_out_to_threat_detection(traces_rows, metrics_rows) -> None:
    """Send the same Neo4j telemetry evidence to the threat decision point."""
    if not THREAT_DETECTION_URL:
        return
    evidence = []
    for timestamp, trace_id, _, _, service, span, _, duration, status_code, _, _ in traces_rows:
        evidence.append({"event_id": trace_id, "telemetry_data": {"service": service, "span": span, "duration_ms": duration, "status_code": status_code, "timestamp": timestamp.isoformat()}})
    for timestamp, name, _, value, unit, attributes in metrics_rows:
        evidence.append({"telemetry_data": {"metric_name": name, "metric_value": value, "unit": unit, "timestamp": timestamp.isoformat(), **json.loads(attributes)}})
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            for item in evidence:
                await client.post(THREAT_DETECTION_URL, json=item)
    except httpx.HTTPError as exc:
        print(f"[Telemetry Ingestor] Threat-detection fan-out failed: {exc}")

def parse_otel_attributes(attributes_list) -> Dict[str, Any]:
    attributes = {}
    if not attributes_list or not isinstance(attributes_list, list):
        return attributes
    for attr in attributes_list:
        key = attr.get("key")
        val_wrapper = attr.get("value", {})
        if "stringValue" in val_wrapper:
            val = val_wrapper["stringValue"]
        elif "intValue" in val_wrapper:
            val = int(val_wrapper["intValue"])
        elif "doubleValue" in val_wrapper:
            val = float(val_wrapper["doubleValue"])
        elif "boolValue" in val_wrapper:
            val = bool(val_wrapper["boolValue"])
        else:
            val = list(val_wrapper.values())[0] if val_wrapper else None
        attributes[key] = val
    return attributes


def parse_traces_payload(payload: Dict[str, Any]):
    rows = []
    detected = []
    
    resource_spans = payload.get("resourceSpans", [])
    if not isinstance(resource_spans, list):
        return rows, detected
        
    for res_span in resource_spans:
        resource = res_span.get("resource", {})
        res_attrs = parse_otel_attributes(resource.get("attributes", []))
        service_name = res_attrs.get("service.name", "unknown_service")
        
        scope_spans = res_span.get("scopeSpans", [])
        if not isinstance(scope_spans, list):
            continue
            
        for scope_span in scope_spans:
            spans = scope_span.get("spans", [])
            if not isinstance(spans, list):
                continue
                
            for span in spans:
                trace_id = span.get("traceId", "")
                span_id = span.get("spanId", "")
                parent_span_id = span.get("parentSpanId", "")
                name = span.get("name", "unnamed")
                kind_id = span.get("kind", 0)
                
                kinds = ["SPAN_KIND_UNSPECIFIED", "SPAN_KIND_INTERNAL", "SPAN_KIND_SERVER", "SPAN_KIND_CLIENT", "SPAN_KIND_PRODUCER", "SPAN_KIND_CONSUMER"]
                kind = kinds[kind_id] if 0 <= kind_id < len(kinds) else str(kind_id)
                
                start_time_nano = int(span.get("startTimeUnixNano", 0))
                end_time_nano = int(span.get("endTimeUnixNano", 0))
                
                start_dt = datetime.datetime.utcfromtimestamp(start_time_nano / 1e9)
                duration_ms = (end_time_nano - start_time_nano) / 1e6
                
                status = span.get("status", {})
                status_code_id = status.get("code", 0)
                status_codes = ["STATUS_CODE_UNSET", "STATUS_CODE_OK", "STATUS_CODE_ERROR"]
                status_code = status_codes[status_code_id] if 0 <= status_code_id < len(status_codes) else str(status_code_id)
                status_message = status.get("message", "")
                
                span_attrs = parse_otel_attributes(span.get("attributes", []))
                all_attrs = {**res_attrs, **span_attrs}
                
                rows.append([
                    start_dt,
                    trace_id,
                    span_id,
                    parent_span_id,
                    service_name,
                    name,
                    kind,
                    duration_ms,
                    status_code,
                    status_message,
                    json.dumps(all_attrs)
                ])
                
                if duration_ms > 1000.0:
                    detected.append({
                        "type": "CRITICAL LATENCY",
                        "service": service_name,
                        "metric_or_span": name,
                        "details": f"Latency was {duration_ms:.1f}ms (threshold 1000ms)",
                        "timestamp": start_dt.strftime("%Y-%m-%d %H:%M:%S")
                    })
                if status_code == "STATUS_CODE_ERROR":
                    detected.append({
                        "type": "SPAN ERROR",
                        "service": service_name,
                        "metric_or_span": name,
                        "details": f"Failed with status error: {status_message or 'No message'}",
                        "timestamp": start_dt.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
    return rows, detected


def parse_metrics_payload(payload: Dict[str, Any]):
    global latest_device_metrics
    rows = []
    detected = []
    
    resource_metrics = payload.get("resourceMetrics", [])
    if not isinstance(resource_metrics, list):
        return rows, detected
        
    for res_metric in resource_metrics:
        resource = res_metric.get("resource", {})
        res_attrs = parse_otel_attributes(resource.get("attributes", []))
        service_name = res_attrs.get("service.name", "unknown_service")
        
        scope_metrics = res_metric.get("scopeMetrics", [])
        if not isinstance(scope_metrics, list):
            continue
            
        for scope_metric in scope_metrics:
            metrics = scope_metric.get("metrics", [])
            if not isinstance(metrics, list):
                continue
                
            for m in metrics:
                metric_name = m.get("name", "unnamed")
                description = m.get("description", "")
                unit = m.get("unit", "")
                
                data_points = []
                metric_type = "UNKNOWN"
                
                if "gauge" in m:
                    metric_type = "GAUGE"
                    data_points = m["gauge"].get("dataPoints", [])
                elif "sum" in m:
                    metric_type = "SUM"
                    data_points = m["sum"].get("dataPoints", [])
                elif "histogram" in m:
                    metric_type = "HISTOGRAM"
                    data_points = m["histogram"].get("dataPoints", [])
                
                for dp in data_points:
                    time_nano = int(dp.get("timeUnixNano", 0))
                    dp_dt = datetime.datetime.utcfromtimestamp(time_nano / 1e9)
                    
                    value = 0.0
                    if "asDouble" in dp:
                        value = float(dp["asDouble"])
                    elif "asInt" in dp:
                        value = float(dp["asInt"])
                    elif "count" in dp:
                        value = float(dp["count"])
                        
                    dp_attrs = parse_otel_attributes(dp.get("attributes", []))
                    all_attrs = {**res_attrs, **dp_attrs, "description": description}
                    
                    rows.append([
                        dp_dt,
                        metric_name,
                        metric_type,
                        value,
                        unit,
                        json.dumps(all_attrs)
                    ])
                    
                    # Update local state cache for live metrics display
                    if service_name not in latest_device_metrics:
                        latest_device_metrics[service_name] = {}
                    latest_device_metrics[service_name][metric_name] = {
                        "value": value,
                        "unit": unit,
                        "timestamp": dp_dt.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    # Anomaly alerts for critical metrics
                    if any(term in metric_name.lower() for term in ["cpu.utilization", "memory.utilization"]):
                        if value > 90.0:
                            detected.append({
                                "type": "HIGH RESOURCE UTILIZATION",
                                "service": service_name,
                                "metric_or_span": metric_name,
                                "details": f"Utilization value {value:.1f}% exceeded limit (90%)",
                                "timestamp": dp_dt.strftime("%Y-%m-%d %H:%M:%S")
                            })
                            
    return rows, detected


@app.post("/v1/traces", status_code=status.HTTP_200_OK)
async def ingest_traces(request: Request):
    try:
        payload = await request.json()
        rows, detected_anomalies = parse_traces_payload(payload)
        
        if rows:
            store_telemetry_graph(rows, [])
            await fan_out_to_threat_detection(rows, [])
            
            stats["traces_received"] += len(rows)
            stats["anomalies_detected"] += len(detected_anomalies)
            stats["last_ingest_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            anomalies.extend(detected_anomalies)
            del anomalies[:-50]
            
            return JSONResponse(content={"status": "success", "spans_ingested": len(rows)})
            
        return JSONResponse(content={"status": "empty", "spans_ingested": 0})
    except Exception as e:
        print(f"[Telemetry Ingestor] Error ingesting traces: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "error", "message": str(e)}
        )


@app.post("/v1/metrics", status_code=status.HTTP_200_OK)
async def ingest_metrics(request: Request):
    try:
        payload = await request.json()
        rows, detected_anomalies = parse_metrics_payload(payload)
        
        if rows:
            store_telemetry_graph([], rows)
            await fan_out_to_threat_detection([], rows)
            
            stats["metrics_received"] += len(rows)
            stats["anomalies_detected"] += len(detected_anomalies)
            stats["last_ingest_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            anomalies.extend(detected_anomalies)
            del anomalies[:-50]
            
            return JSONResponse(content={"status": "success", "metrics_ingested": len(rows)})
            
        return JSONResponse(content={"status": "empty", "metrics_ingested": 0})
    except Exception as e:
        print(f"[Telemetry Ingestor] Error ingesting metrics: {e}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"status": "error", "message": str(e)}
        )


@app.get("/api/stats")
async def get_stats():
    return JSONResponse(content={
        "stats": stats, 
        "anomalies": anomalies, 
        "devices": latest_device_metrics
    })


@app.get("/", response_class=HTMLResponse)
async def index():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ULPF Telemetry Ingestion Hub</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #090b11;
                --card-bg: rgba(20, 25, 40, 0.6);
                --card-border: rgba(255, 255, 255, 0.08);
                --primary: #8a2be2;
                --primary-glow: rgba(138, 43, 226, 0.3);
                --success: #00e676;
                --warning: #ffb300;
                --danger: #ff1744;
                --text: #f1f1f1;
                --text-muted: #8b9bb4;
            }
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            body {
                background: radial-gradient(circle at 50% 0%, #171629 0%, var(--bg) 70%);
                color: var(--text);
                font-family: 'Outfit', sans-serif;
                min-height: 100vh;
                padding: 2.5rem;
                overflow-x: hidden;
            }
            header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 2.5rem;
                padding-bottom: 1.5rem;
                border-bottom: 1px solid var(--card-border);
            }
            .brand h1 {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 2.2rem;
                font-weight: 800;
                background: linear-gradient(135deg, #fff 0%, #b286fd 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                letter-spacing: -0.5px;
            }
            .brand p {
                color: var(--text-muted);
                font-size: 0.95rem;
                margin-top: 4px;
            }
            .badge {
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                padding: 6px 12px;
                border-radius: 20px;
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 0.85rem;
                color: var(--success);
            }
            .badge-dot {
                width: 8px;
                height: 8px;
                background: var(--success);
                border-radius: 50%;
                box-shadow: 0 0 10px var(--success);
                animation: pulse 1.8s infinite;
            }
            @keyframes pulse {
                0% { transform: scale(0.9); opacity: 0.6; }
                50% { transform: scale(1.2); opacity: 1; }
                100% { transform: scale(0.9); opacity: 0.6; }
            }
            .grid-stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }
            .card {
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                backdrop-filter: blur(10px);
                border-radius: 16px;
                padding: 1.5rem;
                transition: transform 0.3s ease, border-color 0.3s ease;
                position: relative;
                overflow: hidden;
            }
            .card::before {
                content: '';
                position: absolute;
                top: 0; left: 0; width: 100%; height: 100%;
                background: linear-gradient(180deg, rgba(255,255,255,0.03) 0%, transparent 100%);
                pointer-events: none;
            }
            .card:hover {
                transform: translateY(-3px);
                border-color: rgba(138, 43, 226, 0.4);
            }
            .card-label {
                color: var(--text-muted);
                font-size: 0.85rem;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            .card-value {
                font-size: 2.5rem;
                font-weight: 800;
                margin-top: 0.4rem;
                font-family: 'Space Grotesk', sans-serif;
            }
            .card-metrics { color: #536dfe; }
            .card-traces { color: #00b0ff; }
            .card-anomalies { color: var(--danger); }
            .card-timestamp { font-size: 1.1rem; color: var(--text); font-weight: 600; margin-top: 0.8rem; }
            
            .dashboard-section {
                background: var(--card-bg);
                border: 1px solid var(--card-border);
                border-radius: 20px;
                padding: 2rem;
                backdrop-filter: blur(12px);
                margin-bottom: 2rem;
            }
            .section-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.5rem;
            }
            .section-title {
                font-family: 'Space Grotesk', sans-serif;
                font-size: 1.4rem;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .devices-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 1.5rem;
            }
            .device-card {
                background: rgba(10, 12, 18, 0.7);
                border: 1px solid var(--card-border);
                border-radius: 16px;
                padding: 1.8rem;
                font-family: 'Space Grotesk', sans-serif;
            }
            .device-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                padding-bottom: 0.8rem;
                margin-bottom: 1.2rem;
            }
            .device-name {
                font-size: 1.4rem;
                font-weight: 700;
                color: #fff;
            }
            .device-status {
                font-size: 0.8rem;
                color: var(--success);
                background: rgba(0, 230, 118, 0.1);
                padding: 4px 8px;
                border-radius: 6px;
                font-weight: bold;
                border: 1px solid rgba(0, 230, 118, 0.2);
            }
            .metric-row {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 0.5rem 0;
                border-bottom: 1px dashed rgba(255, 255, 255, 0.04);
            }
            .metric-row:last-child {
                border-bottom: none;
            }
            .metric-label {
                color: var(--text-muted);
                font-family: 'Outfit', sans-serif;
                font-size: 0.95rem;
            }
            .metric-val {
                font-weight: 700;
                color: #fff;
                font-size: 1.05rem;
            }
            .table-container {
                overflow-x: auto;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                text-align: left;
            }
            th {
                color: var(--text-muted);
                font-size: 0.85rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                padding: 1rem;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            }
            td {
                padding: 1.2rem 1rem;
                border-bottom: 1px solid rgba(255, 255, 255, 0.03);
                font-size: 0.95rem;
            }
            tr:last-child td {
                border-bottom: none;
            }
            tr:hover td {
                background: rgba(255, 255, 255, 0.02);
            }
            .anomaly-badge {
                padding: 4px 10px;
                border-radius: 6px;
                font-size: 0.75rem;
                font-weight: 700;
                letter-spacing: 0.5px;
                text-transform: uppercase;
                display: inline-block;
            }
            .badge-latency {
                background: rgba(255, 23, 68, 0.15);
                color: var(--danger);
                border: 1px solid rgba(255, 23, 68, 0.3);
            }
            .badge-error {
                background: rgba(255, 179, 0, 0.15);
                color: var(--warning);
                border: 1px solid rgba(255, 179, 0, 0.3);
            }
            .badge-util {
                background: rgba(138, 43, 226, 0.15);
                color: #b286fd;
                border: 1px solid rgba(138, 43, 226, 0.3);
            }
            .no-data {
                text-align: center;
                padding: 3rem;
                color: var(--text-muted);
                font-size: 1rem;
                grid-column: 1 / -1;
            }
        </style>
    </head>
    <body>
        <header>
            <div class="brand">
                <h1>Universal Log Pre-processing Framework</h1>
                <p>OpenTelemetry Metric & Trace Analytics Ingestor</p>
            </div>
            <div class="badge">
                <div class="badge-dot"></div>
                Live Telemetry Receiver Active
            </div>
        </header>

        <div class="grid-stats">
            <div class="card">
                <div class="card-label">Metrics Ingested</div>
                <div class="card-value card-metrics" id="stat-metrics">0</div>
            </div>
            <div class="card">
                <div class="card-label">Traces Ingested</div>
                <div class="card-value card-traces" id="stat-traces">0</div>
            </div>
            <div class="card">
                <div class="card-label">Anomalies Logged</div>
                <div class="card-value card-anomalies" id="stat-anomalies">0</div>
            </div>
            <div class="card">
                <div class="card-label">Last Transmission</div>
                <div class="card-timestamp" id="stat-timestamp">N/A</div>
            </div>
        </div>

        <section class="dashboard-section">
            <div class="section-header">
                <h2 class="section-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: #00e676;">
                        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                        <line x1="6" y1="6" x2="6.01" y2="6"/>
                        <line x1="6" y1="18" x2="6.01" y2="18"/>
                    </svg>
                    Active Devices Telemetry
                </h2>
            </div>
            <div class="devices-grid" id="devices-container">
                <div class="no-data">Listening for active device metric beacons...</div>
            </div>
        </section>

        <section class="dashboard-section">
            <div class="section-header">
                <h2 class="section-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--danger);">
                        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                    Real-time Telemetry Anomalies
                </h2>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Severity / Type</th>
                            <th>Service</th>
                            <th>Metric / Operation</th>
                            <th>Anomaly Details</th>
                        </tr>
                    </thead>
                    <tbody id="anomalies-body">
                        <tr>
                            <td colspan="5" class="no-data">Listening for inbound OpenTelemetry streams...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </section>

        <script>
            async function updateDashboard() {
                try {
                    const response = await fetch('/api/stats');
                    const data = await response.json();
                    
                    // Update counters
                    document.getElementById('stat-metrics').innerText = data.stats.metrics_received.toLocaleString();
                    document.getElementById('stat-traces').innerText = data.stats.traces_received.toLocaleString();
                    document.getElementById('stat-anomalies').innerText = data.stats.anomalies_detected.toLocaleString();
                    document.getElementById('stat-timestamp').innerText = data.stats.last_ingest_time;
                    
                    // Update Devices Grid
                    const devContainer = document.getElementById('devices-container');
                    const deviceNames = Object.keys(data.devices);
                    
                    if (deviceNames.length === 0) {
                        devContainer.innerHTML = '<div class="no-data">Listening for active device metric beacons...</div>';
                    } else {
                        let devHtml = '';
                        deviceNames.forEach(name => {
                            const metrics = data.devices[name];
                            
                            // Map to variables (with format matching requested layout)
                            const cpu = metrics["cpu.utilization"] ? `${metrics["cpu.utilization"].value.toFixed(1)} %` : 'N/A';
                            const memory = metrics["memory.utilization"] ? `${metrics["memory.utilization"].value.toFixed(1)} %` : 'N/A';
                            const netIn = metrics["network.in"] ? `${metrics["network.in"].value.toFixed(1)} MB/s` : 'N/A';
                            const netOut = metrics["network.out"] ? `${metrics["network.out"].value.toFixed(1)} MB/s` : 'N/A';
                            const packetsIn = metrics["packets.in"] ? `${metrics["packets.in"].value.toLocaleString()}` : 'N/A';
                            const packetsOut = metrics["packets.out"] ? `${metrics["packets.out"].value.toLocaleString()}` : 'N/A';
                            const activeConn = metrics["active_connections"] ? `${metrics["active_connections"].value}` : 'N/A';
                            const pktErrors = metrics["packet_errors"] ? `${metrics["packet_errors"].value}` : 'N/A';
                            
                            devHtml += `
                                <div class="device-card">
                                    <div class="device-header">
                                        <div class="device-name">${name}</div>
                                        <div class="device-status">ONLINE</div>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">CPU Usage:</span>
                                        <span class="metric-val">${cpu}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Memory Usage:</span>
                                        <span class="metric-val">${memory}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Network In:</span>
                                        <span class="metric-val">${netIn}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Network Out:</span>
                                        <span class="metric-val">${netOut}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Packets In:</span>
                                        <span class="metric-val">${packetsIn}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Packets Out:</span>
                                        <span class="metric-val">${packetsOut}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Active Connections:</span>
                                        <span class="metric-val">${activeConn}</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="metric-label">Packet Errors:</span>
                                        <span class="metric-val" style="${pktErrors !== 'N/A' && parseInt(pktErrors) > 0 ? 'color: var(--danger);' : ''}">${pktErrors}</span>
                                    </div>
                                </div>
                            `;
                        });
                        devContainer.innerHTML = devHtml;
                    }
                    
                    // Update table of anomalies
                    const tbody = document.getElementById('anomalies-body');
                    if (data.anomalies.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="5" class="no-data">Listening for inbound OpenTelemetry streams...</td></tr>';
                        return;
                    }
                    
                    let rowsHtml = '';
                    const reversedAnomalies = [...data.anomalies].reverse();
                    
                    reversedAnomalies.forEach(anomaly => {
                        let badgeClass = 'badge-latency';
                        if (anomaly.type.includes('ERROR')) {
                            badgeClass = 'badge-error';
                        } else if (anomaly.type.includes('UTILIZATION')) {
                            badgeClass = 'badge-util';
                        }
                        
                        rowsHtml += `
                            <tr>
                                <td style="color: var(--text-muted); font-family: monospace;">${anomaly.timestamp}</td>
                                <td><span class="anomaly-badge ${badgeClass}">${anomaly.type}</span></td>
                                <td style="font-weight: 600;">${anomaly.service}</td>
                                <td><code style="background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px;">${anomaly.metric_or_span}</code></td>
                                <td style="color: #cbd5e1;">${anomaly.details}</td>
                            </tr>
                        `;
                    });
                    tbody.innerHTML = rowsHtml;
                } catch (e) {
                    console.error("Dashboard update failed", e);
                }
            }
            
            setInterval(updateDashboard, 2000);
            updateDashboard();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
