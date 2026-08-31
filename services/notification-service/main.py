"""Air-gap friendly notification service for ULPF security alerts.

The service intentionally keeps alert delivery local by default.  It records a
bounded alert history for the dashboard and may forward to an internally hosted
webhook when ``NOTIFICATION_WEBHOOK_URL`` is configured.
"""

from __future__ import annotations

import os
from collections import deque
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID, uuid4

import httpx
import clickhouse_connect
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "MEDIUM"
    description: str = ""
    source: str = "threat-detection"
    event_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class NotificationService:
    def __init__(self) -> None:
        self.alerts: deque[Alert] = deque(maxlen=int(os.getenv("ALERT_HISTORY_SIZE", "200")))
        self.webhook_url = os.getenv("NOTIFICATION_WEBHOOK_URL", "").strip()
        self.clickhouse_host = os.getenv("CLICKHOUSE_HOST", "clickhouse")
        self.clickhouse_port = int(os.getenv("CLICKHOUSE_PORT", "8123"))
        self.clickhouse_db = os.getenv("CLICKHOUSE_DB", "ulpf")
        self._clickhouse = None

    def _persist_clickhouse(self, alert: Alert) -> None:
        """Best-effort persistence for Grafana; local delivery must not depend on it."""
        try:
            if self._clickhouse is None:
                self._clickhouse = clickhouse_connect.get_client(
                    host=self.clickhouse_host, port=self.clickhouse_port,
                    username=os.getenv("CLICKHOUSE_USER", "default"),
                    password=os.getenv("CLICKHOUSE_PASSWORD", ""),
                    database=self.clickhouse_db,
                )
            context = alert.context or {}
            log = context.get("log", {}) if isinstance(context, dict) else {}
            try:
                correlated_events = [str(UUID(alert.event_id))] if alert.event_id else []
            except (ValueError, TypeError, AttributeError):
                correlated_events = []
            self._clickhouse.insert(
                table="alerts",
                data=[[
                    alert.alert_id, alert.timestamp, alert.title, alert.severity,
                    alert.description, str(log.get("src_ip", "")),
                    str(log.get("user_name", "")), correlated_events,
                ]],
                column_names=["alert_id", "timestamp", "rule_name", "severity",
                              "description", "src_ip", "user_name", "correlated_events"],
            )
        except Exception:
            # ClickHouse may still be starting; the in-memory history remains available.
            self._clickhouse = None

    async def deliver(self, alert: Alert) -> dict[str, Any]:
        self.alerts.appendleft(alert)
        self._persist_clickhouse(alert)
        delivered_to = ["local-alert-store"]
        if self.webhook_url:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.post(self.webhook_url, json=alert.model_dump(mode="json"))
                    response.raise_for_status()
                delivered_to.append("internal-webhook")
            except httpx.HTTPError as exc:
                # Preserve the alert even if an optional downstream receiver is unavailable.
                return {"accepted": True, "alert_id": alert.alert_id, "delivered_to": delivered_to, "webhook_error": str(exc)}
        return {"accepted": True, "alert_id": alert.alert_id, "delivered_to": delivered_to}


service = NotificationService()
app = FastAPI(title="ULPF Notification Service", version="1.0.0")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "stored_alerts": len(service.alerts), "webhook_configured": bool(service.webhook_url)}


@app.post("/v1/alerts")
async def create_alert(alert: Alert) -> dict[str, Any]:
    return await service.deliver(alert)


@app.get("/v1/alerts")
async def list_alerts(limit: int = 50) -> list[dict[str, Any]]:
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    return [alert.model_dump(mode="json") for alert in list(service.alerts)[:limit]]
