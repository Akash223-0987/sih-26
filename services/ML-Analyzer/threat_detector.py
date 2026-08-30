from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, Optional

import httpx

try:
    from services.ML_Analyzer.telemetry_connector import TelemetryAggregator
except ImportError:
    from telemetry_connector import TelemetryAggregator

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    def __init__(self, dispatch: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None) -> None:
        self.dispatch = dispatch

    async def send(self, alert: Dict[str, Any]) -> None:
        if self.dispatch is not None:
            await self.dispatch(alert)


class ThreatDetectionService:
    def __init__(self, telemetry: Optional[TelemetryAggregator] = None, notifications: Optional[NotificationDispatcher] = None, prediction_url: str = "http://localhost:8000/predict-threat") -> None:
        self.telemetry = telemetry or TelemetryAggregator()
        self.notifications = notifications or NotificationDispatcher()
        self.prediction_url = prediction_url

    async def evaluate(self, event_id: str, entity_id: Optional[str] = None) -> Dict[str, Any]:
        payload = {"event_id": event_id, "entity_id": entity_id or event_id, **self.telemetry.aggregate(event_id, entity_id)}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.prediction_url, json=payload, timeout=1.0)
                response.raise_for_status()
                prediction = response.json()
            if prediction.get("is_anomaly") and prediction.get("risk_level") in {"MEDIUM", "CRITICAL"}:
                await self.notifications.send({"event_id": event_id, "type": "threat_detection", "prediction": prediction, "telemetry": payload})
            return prediction
        except Exception:
            logger.exception("Threat evaluation failed for event_id=%s", event_id)
            raise
