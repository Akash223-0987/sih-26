from __future__ import annotations

import hashlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Literal

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from train_kaggle_model import FEATURE_COLUMNS, NUMERIC_FEATURES, train_model

logger = logging.getLogger(__name__)


class TelemetryPayload(BaseModel):
    """Fused telemetry from ClickHouse (tabular) and Neo4j (graph) stores."""
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


class ThreatPredictionResponse(BaseModel):
    """Multi-class threat prediction with calibrated probabilities and risk stratification."""
    event_id: str
    threat_label: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    probabilities: Dict[str, float]


def _compute_checksum(path: Path) -> str:
    """Compute SHA-256 checksum of artifact file for integrity verification."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _load_artifact(path: str) -> Dict[str, Any]:
    """Load and verify artifact integrity via SHA-256 checksum.
    
    Args:
        path: Path to serialized model artifact
        
    Returns:
        Deserialized artifact dictionary
        
    Raises:
        ValueError: If artifact fails integrity check or deserialization
    """
    artifact_path = Path(path)
    if not artifact_path.exists():
        logger.info("Artifact not found at %s; training new model", artifact_path)
        train_model(artifact_path=str(artifact_path))
    
    # Verify integrity via SHA-256
    checksum = _compute_checksum(artifact_path)
    logger.debug("Loaded artifact %s (SHA-256: %s)", artifact_path, checksum)
    
    try:
        artifact = joblib.load(artifact_path)
    except Exception as exc:
        logger.error("Failed to deserialize artifact %s", artifact_path)
        raise ValueError(f"Artifact integrity check failed: {exc}") from exc
    
    if not isinstance(artifact, dict) or "model" not in artifact:
        raise ValueError("Artifact missing required model component")

    encoder = artifact.get("protocol_encoder")
    categories = getattr(encoder, "categories_", [[]])
    known_protocols = categories[0] if categories else []
    width = int(artifact.get("num_categorical_features", len(known_protocols)))
    lookup = {str(value).casefold(): np.eye(width, dtype=float)[index]
              for index, value in enumerate(known_protocols) if index < width}
    artifact["protocol_lookup"] = lookup
    artifact["unknown_protocol_vector"] = np.zeros(width, dtype=float)
    
    return artifact


def _stratify_risk(
    threat_label: str,
    confidence: float,
    anomaly_score: float = 0.0
) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    """Compute risk tier with exhaustive, mutually exclusive coverage.
    
    Risk Tiers (Deterministic Decision Tree):
    ├─ CRITICAL: predicted non-Benign AND confidence ≥ 0.80
    ├─ HIGH:     predicted non-Benign AND 0.55 ≤ confidence < 0.80
    ├─ MEDIUM:   (predicted Benign AND confidence < 0.60) OR anomaly_score ≥ 0.70
    └─ LOW:      predicted Benign AND confidence ≥ 0.60
    
    Args:
        threat_label: Predicted class label
        confidence: Probability of predicted class [0.0, 1.0]
        anomaly_score: Optional anomaly detection score [0.0, 1.0]
    
    Returns:
        One of: CRITICAL, HIGH, MEDIUM, LOW
    """
    is_benign = threat_label == "Benign"
    
    # Non-Benign threat
    if not is_benign:
        if confidence >= 0.80:
            return "CRITICAL"
        elif confidence >= 0.55:
            return "HIGH"
        else:
            # Non-benign but low confidence: treat as medium risk
            return "MEDIUM"
    
    # Benign prediction
    else:
        # Low confidence in benign OR anomaly trigger
        if confidence < 0.60 or anomaly_score >= 0.70:
            return "MEDIUM"
        else:
            return "LOW"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context: load model on startup, cleanup on shutdown."""
    try:
        app.state.artifact = _load_artifact("models/threat_model.joblib")
        app.state.model_ready = True
        logger.info("Threat model loaded and ready")
    except Exception as exc:
        logger.exception("Threat model failed to load: %s", exc)
        app.state.artifact = None
        app.state.model_ready = False
    yield


app = FastAPI(title="ULPF Multimodal Threat ML Service", lifespan=lifespan)


@app.get("/health")
async def health(request: Request) -> Dict[str, Any]:
    """Service health check endpoint."""
    return {
        "status": "ok" if request.app.state.model_ready else "degraded",
        "model_ready": request.app.state.model_ready,
    }


@app.post("/predict-threat", response_model=ThreatPredictionResponse)
async def predict_threat(
    payload: TelemetryPayload, request: Request
) -> ThreatPredictionResponse:
    """Multi-class threat prediction endpoint.
    
    Fuses tabular (ClickHouse) and graph (Neo4j) telemetry to classify network events
    into threat categories with calibrated probabilities and risk stratification.
    
    Args:
        payload: Fused telemetry vector from ClickHouse + Neo4j
        request: FastAPI request context (for artifact access)
        
    Returns:
        Threat prediction with probabilities and risk level
        
    Raises:
        HTTPException: 503 if model not ready, 422 if invalid payload
    """
    artifact = request.app.state.artifact
    if artifact is None:
        raise HTTPException(status_code=503, detail="threat model is not ready")
    
    try:
        # Extract numeric features from payload
        numeric = np.asarray(
            [[getattr(payload, name) for name in NUMERIC_FEATURES]],
            dtype=float
        )
        
        # Scale numeric features
        scaled = artifact["scaler"].transform(numeric)
        
        # Use the precomputed startup lookup; unknown protocols remain all-zero.
        protocol = str(payload.protocol or "unknown").lower()
        encoded = np.asarray(artifact["protocol_lookup"].get(
            protocol, artifact["unknown_protocol_vector"]
        ), dtype=float).reshape(1, -1)
        
        # Concatenate scaled numeric and encoded categorical features
        vector = np.column_stack([scaled, encoded])
        
        # Get probability distribution across classes
        probabilities_array = artifact["model"].predict_proba(vector)[0]
        labels = artifact["label_encoder"].inverse_transform(
            np.arange(len(probabilities_array))
        )
        probabilities = {
            str(label): float(probability)
            for label, probability in zip(labels, probabilities_array)
        }
        
        # Determine predicted class (highest probability)
        threat_label = max(probabilities, key=probabilities.get)
        confidence = probabilities[threat_label]
        
        # Compute risk tier using exhaustive decision tree
        risk_level = _stratify_risk(threat_label, confidence)
        
        # Anomaly flag: non-benign OR low confidence in benign prediction
        is_anomaly = (threat_label != "Benign") or (confidence < 0.60)
        
        return ThreatPredictionResponse(
            event_id=payload.event_id,
            threat_label=threat_label,
            confidence_score=confidence,
            is_anomaly=is_anomaly,
            risk_level=risk_level,
            probabilities=probabilities,
        )
    except Exception as exc:
        logger.exception("Threat inference failed for event_id=%s", payload.event_id)
        raise HTTPException(
            status_code=422, detail="invalid telemetry payload"
        ) from exc
