from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

try:
    from services.anomaly_detector.anomaly_engine import HybridAnomalyEngine
except ImportError:
    from anomaly_engine import HybridAnomalyEngine

logger = logging.getLogger(__name__)

app = FastAPI(title="ULPF Unsupervised Anomaly Detection Service")
anomaly_engine = HybridAnomalyEngine()


class AnomalyTelemetryInput(BaseModel):
    event_id: str = "unknown"
    entity_id: str = "unknown"
    bytes_in: float = 0.0
    bytes_out: float = 0.0
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "unknown"
    auth_failures: float = 0.0
    auth_successes: float = 0.0
    in_degree: float = 0.0
    avg_span_duration_ms: float = 0.0
    max_call_depth: float = 0.0
    error_flag: float = 0.0


class AnomalyDetectionResponse(BaseModel):
    event_id: str
    anomaly_score: float = Field(ge=0.0, le=1.0)
    statistical_score: float
    isolation_forest_score: float
    is_anomaly: bool
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    reasons: List[str]


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok", "service": "anomaly-detector"}


@app.post("/detect-anomaly", response_model=AnomalyDetectionResponse)
async def detect_anomaly(input_data: AnomalyTelemetryInput) -> AnomalyDetectionResponse:
    try:
        telemetry_dict = input_data.model_dump()
        result = anomaly_engine.detect(telemetry_dict)
        return AnomalyDetectionResponse(**result)
    except Exception as exc:
        logger.exception("Anomaly detection failed for event_id=%s", input_data.event_id)
        raise HTTPException(status_code=422, detail="Failed to calculate anomaly score") from exc
