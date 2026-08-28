import json
import time
import urllib.request
import secrets
import subprocess

METRIC_URL = "http://localhost:8000/v1/metrics"
TRACE_URL = "http://localhost:8000/v1/traces"

def send_post(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode("utf-8"))
    except Exception as e:
        print(f"Error sending to {url}: {e}")
        return None

def now_ns():
    return int(time.time_ns())

def main():
    print("=" * 60)
    print("1. GENERATING & SENDING OPENTELEMETRY DATA")
    print("=" * 60)

    now = now_ns()
    
    # Define start/end times in nano-seconds
    normal_start = now - 120 * 1000000
    normal_end = now
    
    slow_start = now - 1400 * 1000000
    slow_end = now
    
    error_start = now - 300 * 1000000
    error_end = now

    # Generate a single trace_id for the entire transaction cycle
    trace_id = secrets.token_hex(16)
    
    # Generate unique span_ids for each service/operation
    api_gateway_span_id = secrets.token_hex(8)
    threat_analyzer_span_id = secrets.token_hex(8)
    auth_span_id = secrets.token_hex(8)

    trace_payload = {
        "resourceSpans": [
            # 1. API Gateway Span (Parent Span)
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "api-gateway"}},
                        {"key": "deployment.environment", "value": {"stringValue": "production"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "api-gateway-tracer"},
                        "spans": [
                            {
                                "traceId": trace_id,
                                "spanId": api_gateway_span_id,
                                "name": "POST /analyze",
                                "kind": 2, # SPAN_KIND_SERVER
                                "startTimeUnixNano": str(normal_start),
                                "endTimeUnixNano": str(normal_end),
                                "attributes": [
                                    {"key": "http.status_code", "value": {"intValue": 200}},
                                    {"key": "http.method", "value": {"stringValue": "POST"}}
                                ],
                                "status": {"code": 1} # STATUS_CODE_OK
                            }
                        ]
                    }
                ]
            },
            # 2. Threat Analyzer Span (Child of API Gateway, Slow Duration)
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "threat-analyzer"}},
                        {"key": "deployment.environment", "value": {"stringValue": "production"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "threat-analyzer-tracer"},
                        "spans": [
                            {
                                "traceId": trace_id,
                                "spanId": threat_analyzer_span_id,
                                "parentSpanId": api_gateway_span_id,
                                "name": "analyze-ip",
                                "kind": 2, # SPAN_KIND_SERVER
                                "startTimeUnixNano": str(slow_start),
                                "endTimeUnixNano": str(slow_end),
                                "attributes": [
                                    {"key": "http.status_code", "value": {"intValue": 200}},
                                    {"key": "http.method", "value": {"stringValue": "POST"}},
                                    {"key": "threat.category", "value": {"stringValue": "malware"}}
                                ],
                                "status": {"code": 1} # STATUS_CODE_OK
                            }
                        ]
                    }
                ]
            },
            # 3. Authentication Span (Child of API Gateway, Errors out)
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "authentication"}},
                        {"key": "deployment.environment", "value": {"stringValue": "production"}}
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "authentication-tracer"},
                        "spans": [
                            {
                                "traceId": trace_id,
                                "spanId": auth_span_id,
                                "parentSpanId": api_gateway_span_id,
                                "name": "validate-token",
                                "kind": 2, # SPAN_KIND_SERVER
                                "startTimeUnixNano": str(error_start),
                                "endTimeUnixNano": str(error_end),
                                "attributes": [
                                    {"key": "http.status_code", "value": {"intValue": 500}},
                                    {"key": "http.method", "value": {"stringValue": "POST"}},
                                    {"key": "security.auth_type", "value": {"stringValue": "jwt"}}
                                ],
                                "status": {
                                    "code": 2, # STATUS_CODE_ERROR
                                    "message": "Invalid token signature"
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }

    metric_payload = {
        "resourceMetrics": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "device 1"}},
                        {"key": "host.name", "value": {"stringValue": "node-01-prod"}}
                    ]
                },
                "scopeMetrics": [
                    {
                        "scope": {"name": "system-resources"},
                        "metrics": [
                            {
                                "name": "cpu.utilization",
                                "description": "Current system CPU load",
                                "unit": "%",
                                "gauge": {
                                    "dataPoints": [
                                        {
                                            "timeUnixNano": str(now),
                                            "asDouble": 34.2,
                                            "attributes": [{"key": "core", "value": {"stringValue": "all"}}]
                                        }
                                    ]
                                }
                            },
                            {
                                "name": "memory.utilization",
                                "description": "Current system RAM load",
                                "unit": "%",
                                "gauge": {
                                    "dataPoints": [
                                        {
                                            "timeUnixNano": str(now),
                                            "asDouble": 96.5,
                                            "attributes": [{"key": "memory_type", "value": {"stringValue": "RAM"}}]
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }

    # Send traces
    print(f"[*] Sending distributed trace with Trace ID: {trace_id} ...")
    traces_res = send_post(TRACE_URL, trace_payload)
    print(f"[+] Traces response: {traces_res}")

    # Send metrics
    print("[*] Sending system metrics for 'device 1' ...")
    metrics_res = send_post(METRIC_URL, metric_payload)
    print(f"[+] Metrics response: {metrics_res}\n")

    # 2. Wait for ingestion
    wait_time = 1.5
    print("=" * 60)
    print(f"2. WAITING {wait_time} SECONDS FOR PIPELINE INGESTION")
    print("=" * 60)
    time.sleep(wait_time)
    print("[+] Resuming to fetch data...\n")

    # 3. Fetch trace output from ClickHouse
    print("=" * 60)
    print("3. CLICKHOUSE: GROUPED TRACES OUTPUT")
    print("=" * 60)
    trace_query = (
        f"SELECT service_name, span_name, duration_ms, parent_span_id, status_code, status_message "
        f"FROM ulpf.traces WHERE trace_id = '{trace_id}' "
        f"ORDER BY parent_span_id ASC, timestamp ASC"
    )
    cmd_trace = [
        "docker", "exec", "clickhouse-ulpf", 
        "clickhouse-client", "--query", trace_query, "--format", "TabSeparated"
    ]
    
    try:
        result_trace = subprocess.run(cmd_trace, capture_output=True, text=True, check=True)
        lines = result_trace.stdout.strip().split('\n')
        if not lines or lines == ['']:
            print("[-] No traces found for this Trace ID in ClickHouse yet.")
        else:
            print(f"{'SERVICE':<20} | {'OPERATION':<20} | {'DURATION':<10} | {'PARENT SPAN ID':<20} | {'STATUS':<20} | {'MESSAGE'}")
            print("-" * 110)
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 5:
                    svc, name, dur, parent, status = parts[:5]
                    msg = parts[5] if len(parts) > 5 else ""
                    parent_display = parent if parent else "(Root Span)"
                    print(f"{svc:<20} | {name:<20} | {float(dur):>6.1f} ms | {parent_display:<20} | {status:<20} | {msg}")
    except Exception as e:
        print(f"[-] Failed to execute ClickHouse trace query: {e}")

    print("\n" + "=" * 60)
    print("4. CLICKHOUSE: LATEST METRICS FOR DEVICE 1")
    print("=" * 60)
    metric_query = (
        "SELECT timestamp, metric_name, value, unit "
        "FROM ulpf.metrics WHERE attributes LIKE '%device 1%' "
        "ORDER BY timestamp DESC LIMIT 5"
    )
    cmd_metric = [
        "docker", "exec", "clickhouse-ulpf", 
        "clickhouse-client", "--query", metric_query, "--format", "TabSeparated"
    ]
    
    try:
        result_metric = subprocess.run(cmd_metric, capture_output=True, text=True, check=True)
        lines = result_metric.stdout.strip().split('\n')
        if not lines or lines == ['']:
            print("[-] No metrics found for 'device 1' in ClickHouse.")
        else:
            print(f"{'TIMESTAMP':<25} | {'METRIC NAME':<25} | {'VALUE':<10} | {'UNIT'}")
            print("-" * 75)
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 4:
                    ts, name, val, unit = parts[:4]
                    print(f"{ts:<25} | {name:<25} | {float(val):>8.1f} | {unit}")
    except Exception as e:
        print(f"[-] Failed to execute ClickHouse metric query: {e}")

if __name__ == "__main__":
    main()
