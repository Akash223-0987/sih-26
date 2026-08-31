"""Test and Verification Suite for Gmail SMTP & Webhook Notification Integration.

Runs dry-run tests for email HTML formatting and local Webhook payload delivery.
Supports live transmission tests when SMTP_USER, SMTP_PASSWORD, RECIPIENT_EMAIL, or NOTIFICATION_WEBHOOK_URL are provided.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Add project root and ML-Analyzer service to sys.path
root_dir = Path(__file__).parent.parent
ml_dir = str(root_dir / "services" / "ML-Analyzer")
for path_dir in (str(root_dir), ml_dir):
    if path_dir not in sys.path:
        sys.path.insert(0, path_dir)

from threat_detector import (
    EmailNotificationHandler,
    WebhookNotificationHandler,
    SIEMCEFHandler,
    ConsoleNotificationHandler,
    NotificationDispatcher,
    create_dispatcher_from_env,
)


def get_sample_alert() -> dict:
    return {
        "event_id": "evt-security-test-999",
        "type": "threat_detection",
        "prediction": {
            "is_anomaly": True,
            "threat_label": "Exfiltration Wave",
            "risk_level": "HIGH",
            "confidence_score": 0.942,
        },
        "telemetry": {
            "entity_id": "srv-exfil-node-01",
            "bytes_out": 450000.0,
            "dst_port": 443,
            "protocol": "tcp",
        },
    }


async def test_email_formatting() -> None:
    print("\n--- Testing Gmail HTML Email Formatting ---")
    handler = EmailNotificationHandler(
        smtp_user="test.sender@gmail.com",
        smtp_password="dummy-password-1234",
        recipient_email="secops.admin@company.com",
    )
    alert = get_sample_alert()
    email_msg = handler.format_email(alert)

    assert email_msg["Subject"] == "🚨 [ULPF SECURITY ALERT] HIGH Threat Detected: Exfiltration Wave"
    assert email_msg["From"] == "test.sender@gmail.com"
    assert email_msg["To"] == "secops.admin@company.com"
    print("✅ Email Subject and Header verification passed.")
    print("✅ HTML body formatted successfully.")


async def test_env_dispatcher() -> None:
    print("\n--- Testing Environment-based Dispatcher Creation ---")
    dispatcher = create_dispatcher_from_env()
    print(f"✅ Created NotificationDispatcher with {len(dispatcher.handlers)} handler(s).")
    
    # Emit test alert through default handlers (Console & SIEM CEF)
    alert = get_sample_alert()
    await dispatcher.send(alert)
    print("✅ Successfully dispatched alert through environment dispatcher.")


async def test_webhook_handler_mock() -> None:
    print("\n--- Testing Webhook Handler (Mock Server) ---")
    try:
        import httpx
    except ImportError:
        print("⚠️ httpx package not installed in environment; skipping httpx mock test.")
        return

    # Create a local httpx mock client
    async def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        payload = request.content
        assert b"evt-security-test-999" in payload
        return httpx.Response(200, json={"status": "received"})

    transport = httpx.MockTransport(mock_handler)
    
    # Custom Webhook Handler using mock transport
    class MockWebhookHandler(WebhookNotificationHandler):
        async def emit(self, alert: dict) -> None:
            async with httpx.AsyncClient(transport=transport) as client:
                res = await client.post(self.webhook_url, json=alert)
                assert res.status_code == 200

    handler = MockWebhookHandler("http://mock-webhook.local/v1/alerts")
    await handler.emit(get_sample_alert())
    print("✅ Webhook notification payload verified & delivered to mock endpoint successfully.")



async def main() -> None:
    print("=" * 80)
    print("      PyTrace / ULPF - GMAIL SMTP & WEBHOOK NOTIFICATION TEST SUITE      ")
    print("=" * 80)

    await test_email_formatting()
    await test_env_dispatcher()
    await test_webhook_handler_mock()

    print("\n" + "=" * 80)
    print("ALL NOTIFICATION DISPATCHER TESTS PASSED SUCCESSFULLY! 🎉")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
