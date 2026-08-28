import json
import time
import urllib.request
import secrets

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

def test_traces():
    now = now_ns()
    
    # 1. Normal trace (120ms duration)
    normal_start = now - 120 * 1000000
    normal_end = now
    
    # 2. Slow trace (1.4s duration) -> triggers LATENCY anomaly
    slow_start = now - 1400 * 1000000
    slow_end = now
    
    # 3. Error trace (300ms duration) -> triggers ERROR anomaly
    error_start = now - 300 * 1000000
    error_end = now

    # Generate a single trace_id for the entire transaction cycle
    trace_id = secrets.token_hex(16)
    
    # Generate unique span_ids for each service/operation
    api_gateway_span_id = secrets.token_hex(8)
    threat_analyzer_span_id = secrets.token_hex(8)
    auth_span_id = secrets.token_hex(8)

    payload = {
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
    
    print("Sending test traces...")
    res = send_post(TRACE_URL, payload)
    print("Traces response:", res)

def test_metrics():
    now = now_ns()
    
    payload = {
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
                            # Normal CPU metric
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
                            # Anomaly Memory metric (> 90%)
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
    
    print("Sending test metrics...")
    res = send_post(METRIC_URL, payload)
    print("Metrics response:", res)

if __name__ == "__main__":
    test_traces()
    test_metrics()
