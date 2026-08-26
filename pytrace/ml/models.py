from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class NormalizedLog(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_log: str
    raw_log_sha256: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    event_action: Optional[str] = None
    auth_status: Optional[str] = None
    vendor: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    unmapped_properties: Dict[str, Any] = Field(default_factory=dict)


class InferenceResult(BaseModel):
    normalized: NormalizedLog
    embedding: List[float]
    predicted_label: str
    anomaly_score: float = Field(ge=0.0, le=1.0)
    anomaly: bool
    threat_label: str
    threat_confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=1.0)
    processing_ms: float = Field(ge=0.0)

    @property
    def low_confidence(self) -> bool:
        return self.threat_confidence < 0.60

    @property
    def review_label(self) -> str:
        return "Low Confidence / Review" if self.low_confidence else self.threat_label


class RoutedPayloads(BaseModel):
    clickhouse: Dict[str, Any]
    neo4j: Dict[str, Any]
    siem: Dict[str, Any]


class ProcessedLog(BaseModel):
    inference: InferenceResult
    routes: RoutedPayloads
