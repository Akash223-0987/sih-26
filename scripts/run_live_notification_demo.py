"""Live Notification Dispatcher Runner for Gmail SMTP & HTTP Webhooks.

Run this script to send a live test security threat alert to your Gmail inbox and/or custom Webhook endpoint.

Usage:
    python scripts/run_live_notification_demo.py --email your-email@gmail.com --password "16-char-app-password" --recipient secops@company.com --webhook http://localhost:8080/v1/alerts
"""

from __future__ import annotations

import argparse
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
    load_env_file,
)


def create_sample_threat_alert(threat_type: str = "Data Exfiltration Wave") -> dict:
    return {
        "event_id": "live-alert-evt-101",
        "type": "threat_detection",
        "prediction": {
            "is_anomaly": True,
            "threat_label": threat_type,
            "risk_level": "CRITICAL",
            "confidence_score": 0.968,
        },
        "telemetry": {
            "entity_id": "srv-prod-db-01",
            "bytes_out": 1250000.0,
            "bytes_in": 3400.0,
            "dst_port": 443,
            "protocol": "tcp",
            "src_ip": "192.168.1.105",
        },
    }


async def main() -> None:
    load_env_file()
    parser = argparse.ArgumentParser(description="Live Security Threat Notification Dispatcher")

    parser.add_argument("--email", type=str, default=os.getenv("SMTP_USER", ""), help="Sender Gmail address")
    parser.add_argument("--password", type=str, default=os.getenv("SMTP_PASSWORD", ""), help="Gmail 16-character App Password")
    parser.add_argument("--recipient", type=str, default=os.getenv("RECIPIENT_EMAIL", ""), help="SecOps recipient email address")
    parser.add_argument("--webhook", type=str, default=os.getenv("NOTIFICATION_WEBHOOK_URL", ""), help="HTTP Webhook target URL")
    
    args = parser.parse_args()

    handlers = [ConsoleNotificationHandler(), SIEMCEFHandler()]

    print("\n" + "=" * 85)
    print("        PyTrace / ULPF - LIVE GMAIL SMTP & WEBHOOK NOTIFICATION RUNNER        ")
    print("=" * 85)

    if args.email and args.password and args.recipient:
        print(f"📧 Gmail SMTP Enabled: Sender [{args.email}] -> Recipient [{args.recipient}]")
        handlers.append(
            EmailNotificationHandler(
                smtp_user=args.email,
                smtp_password=args.password,
                recipient_email=args.recipient,
            )
        )
    else:
        print("⚠️ Gmail SMTP Disabled (Provide --email, --password, --recipient or set ENV vars to enable)")

    if args.webhook:
        print(f"🌐 Webhook Enabled: POST -> [{args.webhook}]")
        handlers.append(WebhookNotificationHandler(webhook_url=args.webhook))
    else:
        print("⚠️ Webhook Disabled (Provide --webhook or set NOTIFICATION_WEBHOOK_URL to enable)")

    dispatcher = NotificationDispatcher(handlers=handlers)
    sample_alert = create_sample_threat_alert()

    print("\n🚀 Dispatching Critical Security Threat Alert...")
    await dispatcher.send(sample_alert)

    print("\n" + "=" * 85)
    print("NOTIFICATION DISPATCH COMPLETED SUCCESSFULLY!")
    print("=" * 85 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
