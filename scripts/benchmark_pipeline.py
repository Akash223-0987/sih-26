"""Reproducible local benchmark for the ULPF pipeline and sink formats."""
from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pytrace.adapters.clickhouse_adapter import ClickHouseAdapter
from pytrace.adapters.neo4j_adapter import Neo4jAdapter
from pytrace.ml import ULPFPipeline
from services.pipeline_service import PipelineService


TEMPLATES: List[Tuple[str, str]] = [
    ("vendor=fortinet action=allow src_ip=10.0.0.{n} dst_ip=192.0.2.10 protocol=tcp", "Benign"),
    ("vendor=paloalto action=deny src_ip=10.0.0.{n} dst_ip=192.0.2.11 protocol=tcp", "Benign"),
    ("nmap SYN port scan src_ip=10.0.0.{n} dst_ip=192.0.2.12", "Port Scan"),
    ("ssh failed password invalid user src_ip=10.0.0.{n}", "Brute Force"),
    ("DNS tunneling exfiltration src_ip=10.0.0.{n} dst_ip=192.0.2.13", "Exfiltration"),
    ("psexec remote service lateral movement src_ip=10.0.0.{n} dst_ip=192.0.2.14", "Lateral Movement"),
]


def generate_logs(count: int) -> List[Tuple[str, str]]:
    return [(template.format(n=(index % 240) + 1), label) for index in range(count) for template, label in [TEMPLATES[index % len(TEMPLATES)]]]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=600)
    args = parser.parse_args()
    pipeline = ULPFPipeline()
    logs = generate_logs(max(500, args.count))
    latencies = []
    correct = 0
    for text, expected in logs:
        started = time.perf_counter()
        output = pipeline.process(text).inference
        latencies.append((time.perf_counter() - started) * 1000)
        correct += output.threat_label == expected
        ClickHouseAdapter.format_record(output)
        Neo4jAdapter().transform(output)
    dlq_status, dlq_payload = PipelineService(pipeline).process_message(b"\xff\xfe malformed utf8")
    if dlq_status != "dlq" or dlq_payload["ml_processed"]:
        raise RuntimeError("Malformed raw logs must be routed to the DLQ")
    p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1]
    accuracy = correct / len(logs)
    print(f"records={len(logs)} accuracy={accuracy:.4f} mean_ms={statistics.mean(latencies):.4f} p95_ms={p95:.4f}")
    print(f"latency_sla={'PASS' if p95 <= 2.0 else 'FAIL'} dlq_malformed_handling=PASS sink_format_validation=PASS")
    if p95 > 2.0:
        raise SystemExit("P95 latency SLA failed")


if __name__ == "__main__":
    main()
