from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from anomaly_engine import (
    HybridAnomalyEngine,
    IsolationForestAnomalyDetector,
    StatisticalAnomalyScorer,
)
from main import app as anomaly_app
from threat_detector import (
    ConsoleNotificationHandler,
    EmailNotificationHandler,
    NotificationDispatcher,
    PagerDutyNotificationHandler,
    SIEMCEFHandler,
    ThreatDetectionService,
)


@pytest.fixture
def anomaly_client() -> TestClient:
    with TestClient(anomaly_app) as client:
        yield client


class TestStatisticalAnomalyScorer:
    def test_normal_telemetry_low_z_scores(self) -> None:
        scorer = StatisticalAnomalyScorer()
        telemetry = {
            "bytes_in": 1000.0,
            "bytes_out": 500.0,
            "auth_failures": 0.0,
            "in_degree": 3.0,
        }
        score, reasons = scorer.evaluate(telemetry)
        assert score < 0.50
        assert len(reasons) == 0

    def test_spiked_telemetry_high_z_scores(self) -> None:
        scorer = StatisticalAnomalyScorer()
        telemetry = {
            "bytes_in": 100000.0,
            "bytes_out": 50000.0,
            "auth_failures": 50.0,
            "in_degree": 100.0,
        }
        score, reasons = scorer.evaluate(telemetry)
        assert score >= 0.70
        assert len(reasons) > 0


class TestIsolationForestAnomalyDetector:
    def test_baseline_fit_and_prediction(self) -> None:
        detector = IsolationForestAnomalyDetector()
        assert detector.is_fitted

        normal = {"bytes_in": 1000, "bytes_out": 500, "auth_failures": 0}
        anomaly = {"bytes_in": 999999, "bytes_out": 888888, "auth_failures": 100}

        score_normal = detector.predict_anomaly_score(normal)
        score_anomaly = detector.predict_anomaly_score(anomaly)

        assert 0.0 <= score_normal <= 1.0
        assert 0.0 <= score_anomaly <= 1.0
        assert score_anomaly > score_normal


class TestHybridAnomalyEngine:
    def test_detect_normal(self) -> None:
        engine = HybridAnomalyEngine()
        res = engine.detect({"event_id": "evt-001", "bytes_in": 1000, "bytes_out": 500})
        assert res["event_id"] == "evt-001"
        assert 0.0 <= res["anomaly_score"] <= 1.0
        assert res["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_detect_extreme_outlier(self) -> None:
        engine = HybridAnomalyEngine()
        res = engine.detect({"event_id": "evt-002", "bytes_out": 500000.0, "auth_failures": 30.0})
        assert res["is_anomaly"] is True
        assert res["risk_level"] in {"HIGH", "CRITICAL"}


class TestAnomalyServiceAPI:
    def test_health(self, anomaly_client: TestClient) -> None:
        response = anomaly_client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_detect_anomaly_endpoint(self, anomaly_client: TestClient) -> None:
        payload = {
            "event_id": "api-evt-100",
            "bytes_in": 1200.0,
            "bytes_out": 400.0,
            "protocol": "tcp",
        }
        response = anomaly_client.post("/detect-anomaly", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["event_id"] == "api-evt-100"
        assert 0.0 <= data["anomaly_score"] <= 1.0
        assert data["risk_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestSIEMNotificationHandlers:
    def test_cef_format(self) -> None:
        cef_handler = SIEMCEFHandler()
        alert = {
            "event_id": "cef-evt-001",
            "prediction": {
                "threat_label": "Brute Force",
                "risk_level": "CRITICAL",
                "confidence_score": 0.92,
            },
        }
        formatted = cef_handler.format_cef(alert)
        assert "CEF:0|ULPF|ThreatEngine" in formatted
        assert "Brute Force" in formatted
        assert "RiskTier cs1=CRITICAL" in formatted

    def test_pagerduty_format(self) -> None:
        pd_handler = PagerDutyNotificationHandler("pd-key-12345")
        alert = {
            "event_id": "pd-001",
            "prediction": {
                "threat_label": "Port Scan",
                "risk_level": "HIGH",
                "confidence_score": 0.81,
            },
        }
        payload = pd_handler.format_pagerduty(alert)
        assert payload["routing_key"] == "pd-key-12345"
        assert payload["payload"]["severity"] == "error"
        assert "Port Scan" in payload["payload"]["summary"]

    def test_gmail_email_format(self) -> None:
        email_handler = EmailNotificationHandler(
            smtp_user="secops@gmail.com",
            smtp_password="app_password",
            recipient_email="admin@company.com",
        )
        alert = {
            "event_id": "gmail-001",
            "prediction": {
                "threat_label": "Brute Force",
                "risk_level": "CRITICAL",
                "confidence_score": 0.95,
            },
        }
        msg = email_handler.format_email(alert)
        assert msg["Subject"] == "🚨 [ULPF SECURITY ALERT] CRITICAL Threat Detected: Brute Force"
        assert msg["To"] == "admin@company.com"


