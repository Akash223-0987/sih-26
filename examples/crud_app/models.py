"""
Domain Models representing Perimeter Devices, Security Incidents, and Auth Entities.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DeviceModel:
    id: str
    hostname: str
    ip_address: str
    mac_address: str
    vendor: str  # e.g., Cisco, PaloAlto, Fortinet, Juniper, CheckPoint
    device_type: str  # firewall, router, switch, ips, gateway
    zone: str  # dmz, internal, external, core
    status: str  # active, degraded, maintenance, offline
    firmware_version: str
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass
class IncidentModel:
    id: str
    title: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    status: str  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED
    source_ip: str
    destination_ip: str
    device_id: Optional[str]
    attack_type: str  # PortScan, BruteForce, SQLInjection, DDoS, MalwareBeacon
    description: str
    assigned_to: Optional[str] = None
    remediation_notes: Optional[str] = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)


@dataclass
class UserModel:
    username: str
    full_name: str
    email: str
    role: str  # secops_admin, analyst, auditor, read_only
    is_active: bool = True
    created_at: str = field(default_factory=utc_now_iso)


@dataclass
class AuditRecord:
    id: str
    timestamp: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    status: str
    details: Dict[str, Any]
