"""Threat decision point joining ClickHouse logs with Neo4j telemetry evidence."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field


class EvaluationRequest(BaseModel):
    """Evidence read from the two architecture data stores.

    ``log_data`` is a normalised ClickHouse record. ``telemetry_data`` is the
    metrics/traces context obtained from Neo4j. Either source can initiate
    evaluation, while a correlation rule can submit both together.
    """

    event_id: str | None = None
    log_data: dict[str, Any] = Field(default_factory=dict)
    telemetry_data: dict[str, Any] = Field(default_factory=dict)


class ThreatDetection:
    def __init__(self) -> None:
        self.ml_url = os.getenv("ML_SERVICE_URL", "http://ml-analyzer:8000/v1/infer")
        self.notification_url = os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8000/v1/alerts")
        self.threshold = float(os.getenv("ALERT_RISK_THRESHOLD", "0.70"))

    @staticmethod
    def triage(request: EvaluationRequest) -> list[str]:
        """Cheap deterministic gate; the ML API is called only for suspicion."""
        log = request.log_data
        telemetry = request.telemetry_data
        raw = str(log.get("raw_message", log.get("message", ""))).casefold()
        reasons: list[str] = []
        if str(log.get("severity", "")).upper() in {"HIGH", "CRITICAL"}:
            reasons.append("high-severity log")
        if any(term in raw for term in ("failed password", "brute force", "port scan", "nmap", "malware", "denied")):
            reasons.append("suspicious log pattern")
        if float(telemetry.get("cpu_utilization", telemetry.get("cpu.utilization", 0)) or 0) >= 90:
            reasons.append("critical CPU utilisation")
        if float(telemetry.get("error_rate", 0) or 0) >= 0.10 or str(telemetry.get("status_code", "")).upper() in {"ERROR", "STATUS_CODE_ERROR"}:
            reasons.append("telemetry error signal")
        if float(telemetry.get("avg_span_duration_ms", telemetry.get("duration_ms", 0)) or 0) >= 1000:
            reasons.append("abnormal trace latency")
        return reasons

    @staticmethod
    def _risk_from_result(result: dict[str, Any]) -> tuple[float, str, str]:
        inference = result.get("inference", result)
        risk = float(inference.get("risk_score", inference.get("anomaly_score", 0.0)) or 0.0)
        label = str(inference.get("threat_label", inference.get("classification", "Benign")))
        severity = "CRITICAL" if risk >= .90 else "HIGH" if risk >= .70 else "MEDIUM" if risk >= .45 else "LOW"
        return risk, label, severity

    async def evaluate(self, request: EvaluationRequest) -> dict[str, Any]:
        event_id = request.event_id or str(request.log_data.get("event_id") or uuid4())
        reasons = self.triage(request)
        if not reasons:
            return {
                "event_id": event_id, "evaluated_at": datetime.now(timezone.utc),
                "suspicious": False, "ml_called": False, "alert_sent": False,
                "reason": "No threat-detection rule matched.",
            }

        # The single ML feature document explicitly contains the evidence from
        # ClickHouse and Neo4j, retaining the origin of every feature.
        ml_input = {"log": request.log_data, "telemetry": request.telemetry_data}
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                response = await client.post(self.ml_url, json={"log": ml_input})
                response.raise_for_status()
                result = response.json()
        except httpx.HTTPError as exc:
            return {
                "event_id": event_id, "evaluated_at": datetime.now(timezone.utc),
                "suspicious": True, "ml_called": True, "alert_sent": False,
                "triage_reasons": reasons, "ml_error": str(exc),
            }

        risk, label, severity = self._risk_from_result(result)
        alert_sent = False
        if risk >= self.threshold and label.casefold() not in {"benign", "normal"}:
            alert = {
                "title": f"{label} detected", "severity": severity,
                "description": f"Confirmed after rule triage and ML analysis (risk {risk:.2f}).",
                "source": "threat-detection", "event_id": event_id,
                "context": {"triage_reasons": reasons, "risk_score": risk, "ml_result": result},
            }
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    response = await client.post(self.notification_url, json=alert)
                    response.raise_for_status()
                alert_sent = True
            except httpx.HTTPError:
                pass
        return {
            "event_id": event_id, "evaluated_at": datetime.now(timezone.utc),
            "suspicious": True, "ml_called": True, "triage_reasons": reasons,
            "risk_score": risk, "threat_label": label, "severity": severity,
            "alert_sent": alert_sent, "ml_result": result,
        }


detector = ThreatDetection()
app = FastAPI(title="ULPF Threat Detection", version="1.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "threat-detection"}


@app.post("/v1/evaluate")
async def evaluate(request: EvaluationRequest) -> dict[str, Any]:
    return await detector.evaluate(request)
