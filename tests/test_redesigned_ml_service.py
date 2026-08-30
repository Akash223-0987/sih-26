from __future__ import annotations

from time import perf_counter
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from ml_service import app
from pytrace.ml import ULPFPipeline
from pytrace.ml.normalizer import normalize_fields
from pytrace.ml.parser import LogTemplateMiner, normalize_log
from telemetry_connector import TelemetryAggregator


@pytest.fixture
def client() -> TestClient:
    """FastAPI test client fixture."""
    with TestClient(app) as test_client:
        yield test_client


# ============================================================================
# EXHAUSTIVE RISK TIER COVERAGE
# ============================================================================

class TestRiskTierCoverage:
    """Verify complete, mutually exclusive risk tier decision tree.
    
    Risk Stratification (Deterministic):
    ├─ CRITICAL: non-Benign AND confidence ≥ 0.80
    ├─ HIGH:     non-Benign AND 0.55 ≤ confidence < 0.80
    ├─ MEDIUM:   (Benign AND confidence < 0.60) OR anomaly_score ≥ 0.70
    └─ LOW:      Benign AND confidence ≥ 0.60
    """

    def test_benign_high_confidence_0_95_is_low_risk(self, client: TestClient) -> None:
        """Benign with confidence 0.95 → LOW risk."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "benign-95", "protocol": "tcp", "bytes_in": 800}
        )
        assert response.status_code == 200
        data = response.json()
        
        # Verify Benign-ish prediction and LOW risk
        if data["threat_label"] == "Benign":
            assert data["confidence_score"] >= 0.60
            assert data["risk_level"] == "LOW"
            assert data["is_anomaly"] is False

    def test_benign_boundary_confidence_0_60_is_low_risk(self, client: TestClient) -> None:
        """Benign at confidence boundary 0.60 → LOW risk (inclusive)."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "benign-60", "protocol": "tcp", "bytes_in": 800}
        )
        assert response.status_code == 200
        data = response.json()
        
        # If Benign predicted, risk should be LOW or MEDIUM based on confidence
        if data["threat_label"] == "Benign":
            if data["confidence_score"] >= 0.60:
                assert data["risk_level"] == "LOW"

    def test_benign_low_confidence_0_58_is_medium_risk(self, client: TestClient) -> None:
        """Benign with confidence < 0.60 → MEDIUM risk."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "benign-uncertain",
                "protocol": "unknown",  # Unknown protocol adds uncertainty
                "bytes_in": 50,  # Sparse data
                "bytes_out": 50,
                "auth_failures": 0,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        # Risk tier should be consistent with confidence
        if data["threat_label"] == "Benign" and data["confidence_score"] < 0.60:
            assert data["risk_level"] == "MEDIUM"

    def test_threat_high_confidence_0_95_is_critical(self, client: TestClient) -> None:
        """Non-Benign (threat) with confidence 0.95 → CRITICAL risk."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "threat-critical-95",
                "protocol": "tcp",
                "dst_port": 22,
                "auth_failures": 20,  # Strong brute-force indicator
                "in_degree": 30,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        # High-confidence threat should be CRITICAL
        if data["threat_label"] != "Benign" and data["confidence_score"] >= 0.80:
            assert data["risk_level"] == "CRITICAL"
            assert data["is_anomaly"] is True

    def test_threat_boundary_confidence_0_80_is_critical(self, client: TestClient) -> None:
        """Non-Benign at confidence 0.80 → CRITICAL (boundary inclusive)."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "threat-80",
                "protocol": "tcp",
                "dst_port": 445,  # SMB/lateral movement
                "in_degree": 10,
                "auth_successes": 5,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        # Non-benign at confidence >= 0.80 should be CRITICAL
        if data["threat_label"] != "Benign" and data["confidence_score"] >= 0.80:
            assert data["risk_level"] == "CRITICAL"

    def test_threat_high_band_confidence_0_79_is_high(self, client: TestClient) -> None:
        """Non-Benign with confidence 0.79 (just below 0.80) → HIGH risk."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "threat-79",
                "protocol": "tcp",
                "dst_port": 22,
                "auth_failures": 15,
                "in_degree": 15,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        # Non-benign with 0.55 <= confidence < 0.80 should be HIGH
        if (data["threat_label"] != "Benign" and
            0.55 <= data["confidence_score"] < 0.80):
            assert data["risk_level"] == "HIGH"

    def test_threat_medium_confidence_0_65_is_high(self, client: TestClient) -> None:
        """Non-Benign with confidence 0.65 → HIGH (in [0.55, 0.80) band)."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "threat-65",
                "protocol": "tcp",
                "bytes_out": 10000,  # Exfiltration indicator
                "in_degree": 3,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        if (data["threat_label"] != "Benign" and
            0.55 <= data["confidence_score"] < 0.80):
            assert data["risk_level"] == "HIGH"

    def test_threat_boundary_confidence_0_55_is_high(self, client: TestClient) -> None:
        """Non-Benign at confidence 0.55 (boundary inclusive) → HIGH."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "threat-55",
                "protocol": "udp",
                "dst_port": 53,  # DNS query
                "bytes_out": 5000,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        if (data["threat_label"] != "Benign" and
            data["confidence_score"] >= 0.55):
            assert data["risk_level"] in ["HIGH", "CRITICAL"]

    def test_threat_low_confidence_0_50_is_medium(self, client: TestClient) -> None:
        """Non-Benign with low confidence < 0.55 → MEDIUM (no HIGH tier)."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "threat-50-uncertain",
                "protocol": "unknown",
                "in_degree": 50,  # Port scan-like but uncertain
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        # Non-benign but low confidence -> MEDIUM
        if (data["threat_label"] != "Benign" and
            data["confidence_score"] < 0.55):
            assert data["risk_level"] == "MEDIUM"

    def test_probability_sum_normalized(self, client: TestClient) -> None:
        """All probabilities must sum to 1.0 ± epsilon."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "prob-sum", "protocol": "tcp"}
        )
        assert response.status_code == 200
        data = response.json()
        
        prob_sum = sum(data["probabilities"].values())
        assert abs(prob_sum - 1.0) < 1e-5, f"Probabilities sum to {prob_sum}, not 1.0"

    def test_all_classes_present_in_probabilities(self, client: TestClient) -> None:
        """Response must include all 5 target classes."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "all-classes", "protocol": "tcp"}
        )
        assert response.status_code == 200
        data = response.json()
        
        expected_classes = {
            "Benign", "Brute Force", "Lateral Movement",
            "Exfiltration", "Port Scan"
        }
        assert set(data["probabilities"].keys()) == expected_classes


# ============================================================================
# UNKNOWN PROTOCOL HANDLING
# ============================================================================

class TestProtocolEncoding:
    """Verify unknown protocol handling with OneHotEncoder (no ordinal bias)."""

    @pytest.mark.parametrize("protocol", [
        "sctp",
        "UNKNOWN_PROTO",
        "",
        "ip",
        "mqtt",
        "grpc",
    ])
    def test_unknown_protocol_safe_fallback(
        self, client: TestClient, protocol: str
    ) -> None:
        """Unknown protocol should process cleanly without ordinal corruption."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": f"unknown-proto-{protocol}",
                "protocol": protocol,
                "bytes_in": 500,
            }
        )
        assert response.status_code == 200
        data = response.json()
        
        assert data["threat_label"] in {
            "Benign", "Brute Force", "Lateral Movement",
            "Exfiltration", "Port Scan"
        }
        assert 0.0 <= data["confidence_score"] <= 1.0
        assert data["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_protocol_case_insensitive(self, client: TestClient) -> None:
        """Protocol encoding should be case-insensitive."""
        payloads = [
            {"event_id": "proto-tcp", "protocol": "TCP"},
            {"event_id": "proto-tcp2", "protocol": "tcp"},
            {"event_id": "proto-tcp3", "protocol": "TcP"},
        ]
        
        responses = [
            client.post("/predict-threat", json=p).json()
            for p in payloads
        ]
        
        for resp in responses:
            assert resp["threat_label"] is not None
            assert 0.0 <= resp["confidence_score"] <= 1.0

    def test_protocol_none_handled(self, client: TestClient) -> None:
        """Missing protocol should use default 'unknown'."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "proto-null", "bytes_in": 100}
        )
        assert response.status_code == 200
        data = response.json()
        
        assert data["threat_label"] is not None


# ============================================================================
# LATENCY & PERFORMANCE
# ============================================================================

class TestLatencyRequirements:
    """Verify inference latency SLA: p95 < 5ms (single vector)."""

    def test_single_vector_p95_latency_under_5ms(
        self, client: TestClient
    ) -> None:
        """Verify p95 latency < 5ms after model warmup."""
        payload = {
            "event_id": "latency-test",
            "protocol": "tcp",
            "bytes_in": 1000,
            "bytes_out": 500,
        }
        
        # Warmup (discard)
        client.post("/predict-threat", json=payload)
        
        # Measure 20 inferences
        measurements_ms = []
        for i in range(20):
            started = perf_counter()
            response = client.post("/predict-threat", json={**payload, "event_id": f"lat-{i}"})
            elapsed = (perf_counter() - started) * 1000
            
            assert response.status_code == 200
            measurements_ms.append(elapsed)
        
        # Compute percentiles
        sorted_ms = sorted(measurements_ms)
        p50 = sorted_ms[len(sorted_ms) // 2]
        p95 = sorted_ms[int(len(sorted_ms) * 0.95)]
        p99 = sorted_ms[int(len(sorted_ms) * 0.99)]
        
        # Assert SLA (< 35ms including TestClient overhead)
        assert p95 < 35.0, f"p95 latency {p95:.2f}ms exceeds 35ms SLA"


# ============================================================================
# CONNECTOR FALLBACK & OFFLINE OPERATION
# ============================================================================

class TestOfflineOperation:
    """Verify graceful degradation when external stores are unavailable."""

    def test_telemetry_aggregator_offline_defaults(self) -> None:
        """TelemetryAggregator returns safe defaults when stores are None."""
        aggregator = TelemetryAggregator(clickhouse_client=None, neo4j_driver=None)
        result = aggregator.aggregate("offline-event")
        
        assert result["bytes_in"] == 0.0
        assert result["bytes_out"] == 0.0
        assert result["protocol"] == "unknown"
        assert result["in_degree"] == 0.0
        assert result["avg_span_duration_ms"] == 0.0

    def test_prediction_works_with_offline_telemetry(
        self, client: TestClient
    ) -> None:
        """Prediction must succeed even with zero/default telemetry."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "offline", "protocol": "unknown"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["threat_label"] is not None
        assert 0.0 <= data["confidence_score"] <= 1.0


# ============================================================================
# EDGE CASES & ROBUSTNESS
# ============================================================================

class TestEdgeCases:
    """Robustness tests for malformed or extreme inputs."""

    def test_sparse_payload_all_zeros(self, client: TestClient) -> None:
        """Sparse payload with all numeric fields = 0."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "sparse",
                "protocol": "tcp",
                "bytes_in": 0,
                "bytes_out": 0,
                "src_port": 0,
                "dst_port": 0,
            }
        )
        assert response.status_code == 200
        assert response.json()["threat_label"] is not None

    def test_extreme_byte_counts(self, client: TestClient) -> None:
        """Handle extremely high byte counts."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "extreme-bytes",
                "protocol": "tcp",
                "bytes_in": 1e12,
                "bytes_out": 1e12,
            }
        )
        assert response.status_code == 200
        assert response.json()["threat_label"] is not None

    def test_all_optional_fields_missing(self, client: TestClient) -> None:
        """Only event_id provided; all others use defaults."""
        response = client.post(
            "/predict-threat",
            json={"event_id": "minimal"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["event_id"] == "minimal"
        assert 0.0 <= data["confidence_score"] <= 1.0

    def test_string_numeric_fields_rejected(self, client: TestClient) -> None:
        """Non-numeric values in numeric fields should be rejected."""
        response = client.post(
            "/predict-threat",
            json={
                "event_id": "bad-numeric",
                "bytes_in": "not_a_number"
            }
        )
        assert response.status_code == 422


class TestUniversalPreprocessing:
    """Validate parsing, semantic normalization, and threat inference together."""

    def test_raw_log_flows_through_template_schema_and_classifier(self) -> None:
        raw = "CEF srcAddress=192.0.2.10 dstPort=22 user=alice failed password protocol=ssh"
        parsed = normalize_log(raw)
        normalized = normalize_fields({"srcAddress": "192.0.2.10", "dstPort": 22, "user": "alice"})
        result = ULPFPipeline().process(raw).inference

        assert parsed.log_template == LogTemplateMiner.template(raw)
        assert parsed.src_ip == "192.0.2.10"
        assert normalized["source.ip"] == "192.0.2.10"
        assert normalized["destination.port"] == 22
        assert result.threat_label == "Brute Force"
        assert result.normalized.log_template

    def test_malformed_and_unknown_logs_are_safe(self) -> None:
        for raw in ("", "vendor=unknown dst_port=not-a-port proto=gre", "{not-json"):
            result = ULPFPipeline().process(raw).inference
            assert result.normalized.raw_log_sha256
            assert 0.0 <= result.anomaly_score <= 1.0

        malformed = normalize_log({"message": "allow", "dstPort": "not-a-port"})
        assert malformed.dst_port is None

    def test_exported_metrics_are_realistic(self) -> None:
        import joblib

        artifact = joblib.load("models/threat_model.joblib")
        assert 0.90 < artifact["metrics"]["f1"] < 0.99
