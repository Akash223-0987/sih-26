"""
Service layer containing business logic and enriched telemetry logging for ULPF.
"""

import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from pytrace import logger, update_request_attribute
from examples.crud_app.database import db


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------
# Device Service
# ---------------------------------------------------------

class DeviceService:

    @staticmethod
    def get_all(zone: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        update_request_attribute("operation", "device_list")
        if zone:
            update_request_attribute("filter_zone", zone)
        if status:
            update_request_attribute("filter_status", status)

        devices = db.list_devices(zone=zone, status=status)
        logger.info(
            "Perimeter devices query executed",
            event_type="inventory_query",
            record_count=len(devices),
            zone_filter=zone,
            status_filter=status,
        )
        return devices

    @staticmethod
    def get_by_id(device_id: str) -> Optional[Dict[str, Any]]:
        update_request_attribute("device_id", device_id)
        device = db.get_device(device_id)
        if device:
            logger.info(
                "Perimeter device retrieved",
                event_type="device_lookup_success",
                device_id=device_id,
                hostname=device["hostname"],
                ip_address=device["ip_address"],
                vendor=device["vendor"],
                zone=device["zone"],
            )
        else:
            logger.warn(
                "Perimeter device lookup failed - not found",
                event_type="device_lookup_failed",
                device_id=device_id,
            )
        return device

    @staticmethod
    def create(data: Dict[str, Any], actor: str = "system") -> Dict[str, Any]:
        device_id = f"DEV-{uuid.uuid4().hex[:8].upper()}"
        now = utc_now()

        payload = {
            "id": device_id,
            "hostname": data["hostname"],
            "ip_address": data["ip_address"],
            "mac_address": data["mac_address"],
            "vendor": data["vendor"],
            "device_type": data["device_type"],
            "zone": data.get("zone", "dmz"),
            "status": data.get("status", "active"),
            "firmware_version": data.get("firmware_version", "1.0.0"),
            "tags": data.get("tags", []),
            "created_at": now,
            "updated_at": now,
        }

        update_request_attribute("device_id", device_id)
        update_request_attribute("vendor", data["vendor"])
        update_request_attribute("ip_address", data["ip_address"])

        created = db.create_device(payload)

        # Audit & Telemetry
        db.record_audit(
            actor=actor,
            action="CREATE_DEVICE",
            resource_type="device",
            resource_id=device_id,
            status="SUCCESS",
            details=payload,
        )

        logger.info(
            "New perimeter network asset registered",
            event_type="device_provisioned",
            device_id=device_id,
            hostname=payload["hostname"],
            ip_address=payload["ip_address"],
            vendor=payload["vendor"],
            zone=payload["zone"],
            actor=actor,
        )
        return created

    @staticmethod
    def update(device_id: str, updates: Dict[str, Any], actor: str = "system") -> Optional[Dict[str, Any]]:
        update_request_attribute("device_id", device_id)
        updated = db.update_device(device_id, updates)

        if updated:
            db.record_audit(
                actor=actor,
                action="UPDATE_DEVICE",
                resource_type="device",
                resource_id=device_id,
                status="SUCCESS",
                details=updates,
            )
            logger.info(
                "Perimeter network asset configuration updated",
                event_type="device_updated",
                device_id=device_id,
                updated_fields=list(updates.keys()),
                new_status=updated.get("status"),
                actor=actor,
            )
        else:
            logger.warn(
                "Failed to update device - ID does not exist",
                event_type="device_update_failed",
                device_id=device_id,
                actor=actor,
            )
        return updated

    @staticmethod
    def delete(device_id: str, actor: str = "system") -> bool:
        update_request_attribute("device_id", device_id)
        success = db.delete_device(device_id)

        if success:
            db.record_audit(
                actor=actor,
                action="DELETE_DEVICE",
                resource_type="device",
                resource_id=device_id,
                status="SUCCESS",
                details={"deleted_id": device_id},
            )
            logger.info(
                "Perimeter network asset decommissioned",
                event_type="device_decommissioned",
                device_id=device_id,
                actor=actor,
            )
        else:
            logger.warn(
                "Failed to decommission device - ID not found",
                event_type="device_delete_failed",
                device_id=device_id,
                actor=actor,
            )
        return success


# ---------------------------------------------------------
# Incident Service
# ---------------------------------------------------------

class IncidentService:

    @staticmethod
    def get_all(severity: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        update_request_attribute("operation", "incident_list")
        if severity:
            update_request_attribute("severity", severity)
        if status:
            update_request_attribute("incident_status", status)

        incidents = db.list_incidents(severity=severity, status=status)
        logger.info(
            "Security incidents triage list requested",
            event_type="incident_query",
            match_count=len(incidents),
            severity_filter=severity,
            status_filter=status,
        )
        return incidents

    @staticmethod
    def get_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
        update_request_attribute("incident_id", incident_id)
        incident = db.get_incident(incident_id)
        if incident:
            logger.info(
                "Security incident record retrieved",
                event_type="incident_lookup_success",
                incident_id=incident_id,
                severity=incident["severity"],
                attack_type=incident["attack_type"],
                source_ip=incident["source_ip"],
            )
        else:
            logger.warn(
                "Security incident not found",
                event_type="incident_lookup_failed",
                incident_id=incident_id,
            )
        return incident

    @staticmethod
    def create(data: Dict[str, Any], actor: str = "siem_collector") -> Dict[str, Any]:
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now = utc_now()

        payload = {
            "id": incident_id,
            "title": data["title"],
            "severity": data["severity"].upper(),
            "status": data.get("status", "OPEN").upper(),
            "source_ip": data["source_ip"],
            "destination_ip": data["destination_ip"],
            "device_id": data.get("device_id"),
            "attack_type": data["attack_type"],
            "description": data["description"],
            "assigned_to": data.get("assigned_to"),
            "remediation_notes": data.get("remediation_notes"),
            "created_at": now,
            "updated_at": now,
        }

        update_request_attribute("incident_id", incident_id)
        update_request_attribute("threat_severity", payload["severity"])
        update_request_attribute("threat_source_ip", payload["source_ip"])
        update_request_attribute("threat_type", payload["attack_type"])

        created = db.create_incident(payload)

        # Telemetry & Threat log
        if payload["severity"] in ("HIGH", "CRITICAL"):
            logger.error(
                f"SECURITY THREAT ALERT [{payload['severity']}]: {payload['title']}",
                event_type="threat_alert_triggered",
                incident_id=incident_id,
                severity=payload["severity"],
                source_ip=payload["source_ip"],
                destination_ip=payload["destination_ip"],
                attack_type=payload["attack_type"],
                device_id=payload["device_id"],
            )
        else:
            logger.info(
                f"Security event recorded: {payload['title']}",
                event_type="security_event_logged",
                incident_id=incident_id,
                severity=payload["severity"],
                source_ip=payload["source_ip"],
                destination_ip=payload["destination_ip"],
            )

        db.record_audit(
            actor=actor,
            action="TRIGGER_SECURITY_INCIDENT",
            resource_type="incident",
            resource_id=incident_id,
            status="SUCCESS",
            details=payload,
        )

        return created

    @staticmethod
    def update(incident_id: str, updates: Dict[str, Any], actor: str = "analyst") -> Optional[Dict[str, Any]]:
        update_request_attribute("incident_id", incident_id)
        updated = db.update_incident(incident_id, updates)

        if updated:
            db.record_audit(
                actor=actor,
                action="UPDATE_SECURITY_INCIDENT",
                resource_type="incident",
                resource_id=incident_id,
                status="SUCCESS",
                details=updates,
            )
            logger.info(
                "Security incident status transition",
                event_type="incident_transition",
                incident_id=incident_id,
                new_status=updated.get("status"),
                new_severity=updated.get("severity"),
                assigned_to=updated.get("assigned_to"),
                actor=actor,
            )
        else:
            logger.warn(
                "Failed to update security incident - ID not found",
                event_type="incident_update_failed",
                incident_id=incident_id,
                actor=actor,
            )
        return updated

    @staticmethod
    def delete(incident_id: str, actor: str = "secops_admin") -> bool:
        update_request_attribute("incident_id", incident_id)
        success = db.delete_incident(incident_id)

        if success:
            db.record_audit(
                actor=actor,
                action="DELETE_SECURITY_INCIDENT",
                resource_type="incident",
                resource_id=incident_id,
                status="SUCCESS",
                details={"deleted_id": incident_id},
            )
            logger.info(
                "Security incident purged from active roster",
                event_type="incident_deleted",
                incident_id=incident_id,
                actor=actor,
            )
        else:
            logger.warn(
                "Failed to delete security incident - ID not found",
                event_type="incident_delete_failed",
                incident_id=incident_id,
                actor=actor,
            )
        return success


# ---------------------------------------------------------
# Auth & Identity Service
# ---------------------------------------------------------

class AuthService:

    @staticmethod
    def authenticate(username: str, password: str, client_ip: str = "127.0.0.1") -> Optional[Dict[str, Any]]:
        update_request_attribute("auth_user", username)
        update_request_attribute("client_ip", client_ip)

        user = db.get_user(username)
        # Mock verification for simulation
        valid = (user is not None) and (
            password in ("SecOps#2026!Pass", "password123", "admin123", "secret") or password.startswith("mock_pass_")
        )

        if valid:
            logger.info(
                "User authentication successful",
                event_type="auth_login_success",
                username=username,
                role=user["role"],
                client_ip=client_ip,
            )
            db.record_audit(
                actor=username,
                action="LOGIN",
                resource_type="auth",
                resource_id=username,
                status="SUCCESS",
                details={"client_ip": client_ip},
            )
            return user
        else:
            logger.warn(
                "User authentication failed - Invalid credentials or brute force attempt",
                event_type="auth_login_failed",
                username=username,
                client_ip=client_ip,
                suspicious_activity=(user is None),
            )
            db.record_audit(
                actor=username,
                action="LOGIN_FAILED",
                resource_type="auth",
                resource_id=username,
                status="FAILED",
                details={"client_ip": client_ip},
            )
            return None
