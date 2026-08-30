from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure services are in sys.path
root_dir = Path(__file__).parent.parent
ml_dir = str(root_dir / "services" / "ML-Analyzer")
anomaly_dir = str(root_dir / "services" / "anomaly-detector")
for d in (str(root_dir), ml_dir, anomaly_dir):
    if d not in sys.path:
        sys.path.insert(0, d)

from fastapi.testclient import TestClient
from ml_service import app as ml_app
from anomaly_engine import HybridAnomalyEngine
from threat_detector import SIEMCEFHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ThreatDetectionDemo")


def run_demo() -> None:
    print("\n" + "=" * 90)
    print("      PyTrace / ULPF - MULTIMODAL THREAT & ANOMALY DETECTION ENGINE DEMO      ")
    print("=" * 90 + "\n")

    anomaly_engine = HybridAnomalyEngine()
    cef_handler = SIEMCEFHandler()

    test_scenarios: List[Dict[str, Any]] = [
        {
            "scenario": "1. Normal API Traffic",
            "telemetry": {
                "event_id": "demo-evt-001",
                "entity_id": "srv-web-01",
                "protocol": "tcp",
                "dst_port": 443,
                "bytes_in": 1200.0,
                "bytes_out": 450.0,
                "auth_failures": 0.0,
                "auth_successes": 5.0,
                "in_degree": 3.0,
                "avg_span_duration_ms": 18.5,
                "max_call_depth": 2.0,
            },
        },
        {
            "scenario": "2. SSH Brute Force Attack Wave",
            "telemetry": {
                "event_id": "demo-evt-002",
                "entity_id": "srv-auth-02",
                "protocol": "tcp",
                "dst_port": 22,
                "bytes_in": 3500.0,
                "bytes_out": 1200.0,
                "auth_failures": 18.0,
                "auth_successes": 0.0,
                "in_degree": 4.0,
                "avg_span_duration_ms": 45.0,
                "max_call_depth": 3.0,
            },
        },
        {
            "scenario": "3. Internal Network Port Scan",
            "telemetry": {
                "event_id": "demo-evt-003",
                "entity_id": "workstation-109",
                "protocol": "tcp",
                "dst_port": 53,
                "bytes_in": 800.0,
                "bytes_out": 3200.0,
                "auth_failures": 0.0,
                "in_degree": 28.0,  # High centrality fan-out
                "avg_span_duration_ms": 12.0,
                "max_call_depth": 1.0,
            },
        },
        {
            "scenario": "4. Data Exfiltration via HTTPS",
            "telemetry": {
                "event_id": "demo-evt-004",
                "entity_id": "srv-db-01",
                "protocol": "tcp",
                "dst_port": 443,
                "bytes_in": 2500.0,
                "bytes_out": 450000.0,  # Huge outbound transfer
                "auth_failures": 0.0,
                "in_degree": 2.0,
                "avg_span_duration_ms": 320.0,  # Long session duration
                "max_call_depth": 8.0,
            },
        },
        {
            "scenario": "5. Lateral Movement Traversing Nodes",
            "telemetry": {
                "event_id": "demo-evt-005",
                "entity_id": "srv-admin-01",
                "protocol": "tcp",
                "dst_port": 445,  # SMB
                "bytes_in": 8500.0,
                "bytes_out": 6200.0,
                "auth_failures": 0.0,
                "auth_successes": 4.0,
                "in_degree": 18.0,
                "avg_span_duration_ms": 110.0,
                "max_call_depth": 5.0,
            },
        },
        {
            "scenario": "6. Zero-Day Metric Outlier (Unsupervised)",
            "telemetry": {
                "event_id": "demo-evt-006",
                "entity_id": "srv-custom-app",
                "protocol": "sctp",  # Uncommon protocol
                "dst_port": 9999,
                "bytes_in": 95000.0,
                "bytes_out": 88000.0,
                "auth_failures": 0.0,
                "in_degree": 15.0,
                "avg_span_duration_ms": 500.0,
                "max_call_depth": 12.0,  # Unusually deep trace call graph
            },
        },
    ]

    header = f"{'Scenario':<34} | {'Threat Class':<18} | {'Conf':<6} | {'Anomaly':<7} | {'Risk Tier':<9} | {'Action':<15}"
    print(header)
    print("-" * len(header))

    with TestClient(ml_app) as client:
        for item in test_scenarios:
            scenario = item["scenario"]
            telemetry = item["telemetry"]

            # 1. Supervised Threat Classifier prediction
            ml_resp = client.post("/predict-threat", json=telemetry)
            ml_data = ml_resp.json() if ml_resp.status_code == 200 else {}

            # 2. Unsupervised Hybrid Anomaly Engine detection
            anomaly_res = anomaly_engine.detect(telemetry)

            label = ml_data.get("threat_label", "Unknown")
            conf = ml_data.get("confidence_score", 0.0)
            anomaly_score = anomaly_res.get("anomaly_score", 0.0)
            risk = ml_data.get("risk_level", "LOW")

            if anomaly_score >= 0.70 and risk == "LOW":
                risk = "MEDIUM"

            action = "Dispatch Alert" if risk in {"MEDIUM", "HIGH", "CRITICAL"} else "Log & Persist"

            row = f"{scenario:<34} | {label:<18} | {conf:<6.2f} | {anomaly_score:<7.2f} | {risk:<9} | {action:<15}"
            print(row)

            # Emit Gmail Notification Alert preview for non-benign or anomalous events
            if risk in {"HIGH", "CRITICAL"}:
                print(f"   +-- [Gmail Alert]: Subject: [ULPF SECURITY ALERT] {risk} Threat Detected: {label} -> Sent to Admin Inbox")

    print("\n" + "=" * 90)
    print("All Threat & Anomaly Scenarios Evaluated Successfully!")
    print("=" * 90 + "\n")


if __name__ == "__main__":
    run_demo()
