from __future__ import annotations

import os
import json
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional


import urllib.request
import urllib.error

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


try:
    from services.ML_Analyzer.telemetry_connector import TelemetryAggregator
except ImportError:
    from telemetry_connector import TelemetryAggregator

logger = logging.getLogger(__name__)


class NotificationHandler:
    """Base class for notification channels."""

    async def emit(self, alert: Dict[str, Any]) -> None:
        raise NotImplementedError


class EmailNotificationHandler(NotificationHandler):
    """Sends HTML threat alert emails via SMTP (e.g., Gmail SMTP)."""

    def __init__(
        self,
        smtp_user: str,
        smtp_password: str,
        recipient_email: str,
        smtp_host: str = "smtp.gmail.com",
        smtp_port: int = 587,
    ) -> None:
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.recipient_email = recipient_email
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port

    def format_email(self, alert: Dict[str, Any]) -> MIMEMultipart:
        prediction = alert.get("prediction", {})
        event_id = alert.get("event_id", "unknown")
        label = prediction.get("threat_label", "Unknown")
        risk = prediction.get("risk_level", "LOW")
        conf = float(prediction.get("confidence_score", 0.0))

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [ULPF SECURITY ALERT] {risk} Threat Detected: {label}"
        msg["From"] = self.smtp_user
        msg["To"] = self.recipient_email

        html_content = f"""
        <html>
          <body style="font-family: Arial, sans-serif; padding: 20px; color: #333;">
            <h2 style="color: #d9534f;">🚨 Security Threat Alert Dispatched</h2>
            <table style="border-collapse: collapse; width: 100%; max-width: 600px;">
              <tr style="background-color: #f2f2f2;"><td style="padding: 10px; font-weight: bold;">Risk Tier:</td><td style="padding: 10px; color: red; font-weight: bold;">{risk}</td></tr>
              <tr><td style="padding: 10px; font-weight: bold;">Threat Category:</td><td style="padding: 10px;">{label}</td></tr>
              <tr style="background-color: #f2f2f2;"><td style="padding: 10px; font-weight: bold;">Confidence Score:</td><td style="padding: 10px;">{conf:.2%}</td></tr>
              <tr><td style="padding: 10px; font-weight: bold;">Event ID:</td><td style="padding: 10px;"><code>{event_id}</code></td></tr>
            </table>
            <p style="margin-top: 20px; font-size: 12px; color: #777;">Sent automatically by PyTrace / ULPF Threat Detection Engine</p>
          </body>
        </html>
        """
        msg.attach(MIMEText(html_content, "html"))
        return msg

    async def emit(self, alert: Dict[str, Any]) -> None:
        try:
            msg = self.format_email(alert)
            clean_pass = self.smtp_password.replace(" ", "").strip()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10.0) as server:
                server.starttls()
                server.login(self.smtp_user, clean_pass)
                server.sendmail(self.smtp_user, [self.recipient_email], msg.as_string())
            logger.info("Alert email successfully sent to %s via Gmail SMTP", self.recipient_email)
        except Exception as exc:
            logger.error("Failed to send alert email to %s: %s", self.recipient_email, exc)




class ConsoleNotificationHandler(NotificationHandler):
    """Logs threat alerts in structured format to standard logger/console."""

    async def emit(self, alert: Dict[str, Any]) -> None:
        prediction = alert.get("prediction", {})
        risk = prediction.get("risk_level", "UNKNOWN")
        label = prediction.get("threat_label", "UNKNOWN")
        conf = prediction.get("confidence_score", 0.0)
        logger.warning(
            "[THREAT ALERT] Risk: %s | Threat: %s | Confidence: %.2f | Event: %s",
            risk, label, conf, alert.get("event_id")
        )


class WebhookNotificationHandler(NotificationHandler):
    """Sends raw JSON webhook payload to custom HTTP endpoint."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def emit(self, alert: Dict[str, Any]) -> None:
        try:
            if httpx is not None:
                async with httpx.AsyncClient() as client:
                    res = await client.post(self.webhook_url, json=alert, timeout=2.0)
                    res.raise_for_status()
            else:
                data = json.dumps(alert).encode("utf-8")
                req = urllib.request.Request(self.webhook_url, data=data, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    pass
        except Exception as exc:
            logger.error("Failed to send webhook notification to %s: %s", self.webhook_url, exc)



class PagerDutyNotificationHandler(NotificationHandler):
    """Dispatches threat alerts via PagerDuty Events API v2."""

    def __init__(self, routing_key: str, events_api_url: str = "https://events.pagerduty.com/v2/enqueue") -> None:
        self.routing_key = routing_key
        self.events_api_url = events_api_url

    def format_pagerduty(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        prediction = alert.get("prediction", {})
        event_id = alert.get("event_id", "unknown")
        label = prediction.get("threat_label", "Unknown")
        risk = prediction.get("risk_level", "LOW")
        conf = float(prediction.get("confidence_score", 0.0))

        severity_map = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning", "LOW": "info"}
        pd_severity = severity_map.get(risk, "warning")

        return {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": f"ulpf-threat-{event_id}",
            "payload": {
                "summary": f"ULPF Threat Triggered: {label} (Risk: {risk}, Conf: {conf:.2%})",
                "source": "PyTrace-ULPF-ThreatEngine",
                "severity": pd_severity,
                "custom_details": {
                    "event_id": event_id,
                    "threat_label": label,
                    "confidence_score": conf,
                    "risk_level": risk,
                    "telemetry": alert.get("telemetry", {}),
                },
            },
        }

    async def emit(self, alert: Dict[str, Any]) -> None:
        payload = self.format_pagerduty(alert)
        try:
            if httpx is not None:
                async with httpx.AsyncClient() as client:
                    res = await client.post(self.events_api_url, json=payload, timeout=2.0)
                    res.raise_for_status()
            else:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(self.events_api_url, data=data, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    pass
        except Exception as exc:
            logger.error("Failed to send PagerDuty alert: %s", exc)




class SIEMCEFHandler(NotificationHandler):
    """Formats and dispatches alerts in Common Event Format (CEF) for SIEM systems."""

    def format_cef(self, alert: Dict[str, Any]) -> str:
        prediction = alert.get("prediction", {})
        event_id = alert.get("event_id", "unknown")
        label = prediction.get("threat_label", "Unknown")
        risk = prediction.get("risk_level", "LOW")
        score = int(prediction.get("confidence_score", 0.0) * 100)

        severity_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 5, "LOW": 2}
        sev = severity_map.get(risk, 1)

        cef = (
            f"CEF:0|ULPF|ThreatEngine|1.0|{label}|{label} Detected|{sev}|"
            f"externalId={event_id} cs1Label=RiskTier cs1={risk} "
            f"cn1Label=Confidence cn1={score}"
        )
        return cef

    async def emit(self, alert: Dict[str, Any]) -> None:
        cef_string = self.format_cef(alert)
        logger.info("[SIEM CEF LOG] %s", cef_string)


class NotificationDispatcher:
    def __init__(
        self,
        dispatch: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
        handlers: Optional[List[NotificationHandler]] = None,
    ) -> None:
        self.dispatch = dispatch
        self.handlers: List[NotificationHandler] = handlers or [ConsoleNotificationHandler()]

    async def send(self, alert: Dict[str, Any]) -> None:
        if self.dispatch is not None:
            await self.dispatch(alert)
        for handler in self.handlers:
            try:
                await handler.emit(alert)
            except Exception as exc:
                logger.error("Notification handler failed: %s", exc)


def load_env_file(env_file_path: Optional[str] = None) -> None:
    """Loads key-value pairs from a .env file into os.environ if present."""
    if env_file_path is None:
        try:
            from pathlib import Path
            root = Path(__file__).resolve().parent.parent.parent
            candidate = root / ".env"
            if candidate.is_file():
                env_file_path = str(candidate)
        except Exception:
            pass

    if env_file_path and os.path.exists(env_file_path):
        with open(env_file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v


def create_dispatcher_from_env() -> NotificationDispatcher:
    """Factory creating a NotificationDispatcher equipped with handlers derived from environment vars."""
    load_env_file()
    handlers: List[NotificationHandler] = [ConsoleNotificationHandler(), SIEMCEFHandler()]

    # Check for Gmail / SMTP environment configuration
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASSWORD", "").strip()
    recipient = os.getenv("RECIPIENT_EMAIL", "").strip()
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))

    if smtp_user and smtp_pass and recipient and "your-email" not in smtp_user:
        logger.info("Initializing Gmail SMTP Notification Handler for %s", recipient)
        handlers.append(
            EmailNotificationHandler(
                smtp_user=smtp_user,
                smtp_password=smtp_pass,
                recipient_email=recipient,
                smtp_host=smtp_host,
                smtp_port=smtp_port,
            )
        )

    # Check for HTTP Webhook environment configuration
    webhook_url = os.getenv("NOTIFICATION_WEBHOOK_URL", "").strip()
    if webhook_url:
        logger.info("Initializing Webhook Notification Handler for %s", webhook_url)
        handlers.append(WebhookNotificationHandler(webhook_url=webhook_url))

    return NotificationDispatcher(handlers=handlers)




class ThreatDetectionService:
    def __init__(
        self,
        telemetry: Optional[TelemetryAggregator] = None,
        notifications: Optional[NotificationDispatcher] = None,
        prediction_url: str = "http://localhost:8000/predict-threat",
    ) -> None:
        self.telemetry = telemetry or TelemetryAggregator()
        self.notifications = notifications or create_dispatcher_from_env()
        self.prediction_url = prediction_url


    async def evaluate(self, event_id: str, entity_id: Optional[str] = None) -> Dict[str, Any]:
        payload = {"event_id": event_id, "entity_id": entity_id or event_id, **self.telemetry.aggregate(event_id, entity_id)}
        try:
            if httpx is not None:
                async with httpx.AsyncClient() as client:
                    response = await client.post(self.prediction_url, json=payload, timeout=2.0)
                    response.raise_for_status()
                    prediction = response.json()
            else:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(self.prediction_url, data=data, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    prediction = json.loads(resp.read().decode("utf-8"))

            if prediction.get("is_anomaly") and prediction.get("risk_level") in {"MEDIUM", "HIGH", "CRITICAL"}:
                await self.notifications.send({"event_id": event_id, "type": "threat_detection", "prediction": prediction, "telemetry": payload})
            return prediction
        except Exception:
            logger.exception("Threat evaluation failed for event_id=%s", event_id)
            raise


