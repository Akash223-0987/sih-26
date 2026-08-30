"""
Database Storage Layer using thread-safe SQLite for CRUD operations.
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from examples.crud_app.config import settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DatabaseManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(DatabaseManager, cls).__new__(cls)
                cls._instance._init_db()
            return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        self.db_path = settings.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Devices Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL UNIQUE,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    zone TEXT NOT NULL,
                    status TEXT NOT NULL,
                    firmware_version TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Incidents Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    device_id TEXT,
                    attack_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    assigned_to TEXT,
                    remediation_notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            """)

            # Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    full_name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
            """)

            # Audit Trail Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            """)

            conn.commit()

        self._seed_data()

    def _seed_data(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Seed Users
            users = [
                ("admin", "Security Administrator", "admin@ntro-soc.gov.in", "pbkdf2:admin_hash", "secops_admin", 1, utc_now()),
                ("analyst_vikram", "Vikram Rathore", "vikram@soc.gov.in", "pbkdf2:user_hash", "analyst", 1, utc_now()),
                ("auditor_ananya", "Ananya Sharma", "ananya@compliance.gov.in", "pbkdf2:audit_hash", "auditor", 1, utc_now()),
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO users (username, full_name, email, password_hash, role, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, users)

            # Seed Devices
            devices = [
                (
                    "DEV-1001",
                    "fw-edge-delhi-01.gov.in",
                    "10.100.1.1",
                    "00:50:56:a1:00:01",
                    "PaloAlto",
                    "firewall",
                    "dmz",
                    "active",
                    "PAN-OS 11.0.2",
                    json.dumps(["edge", "perimeter", "delhi-dc"]),
                    utc_now(),
                    utc_now(),
                ),
                (
                    "DEV-1002",
                    "cisco-core-rtr-02.gov.in",
                    "10.100.1.254",
                    "00:50:56:b2:00:02",
                    "Cisco",
                    "router",
                    "core",
                    "active",
                    "IOS-XE 17.9.3",
                    json.dumps(["core", "backbone", "delhi-dc"]),
                    utc_now(),
                    utc_now(),
                ),
                (
                    "DEV-1003",
                    "forti-ips-cluster-01.gov.in",
                    "10.100.2.10",
                    "00:50:56:c3:00:03",
                    "Fortinet",
                    "ips",
                    "dmz",
                    "active",
                    "FortiOS 7.4.1",
                    json.dumps(["ips", "waf", "mumbai-dr"]),
                    utc_now(),
                    utc_now(),
                ),
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO devices (id, hostname, ip_address, mac_address, vendor, device_type, zone, status, firmware_version, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, devices)

            # Seed Incidents
            incidents = [
                (
                    "INC-8001",
                    "SYN Flood anomaly detected on Gateway",
                    "CRITICAL",
                    "INVESTIGATING",
                    "198.51.100.77",
                    "10.100.1.1",
                    "DEV-1001",
                    "DDoS",
                    "Inbound rate exceeded 1.2M pps from ASN 45211",
                    "analyst_vikram",
                    "Mitigation rule applied at BGP tier.",
                    utc_now(),
                    utc_now(),
                ),
                (
                    "INC-8002",
                    "Malicious User Agent crawling /admin",
                    "MEDIUM",
                    "RESOLVED",
                    "203.0.113.199",
                    "10.100.2.10",
                    "DEV-1003",
                    "PortScan",
                    "Automated Nikto / SQLMap scan signatures matched",
                    "analyst_vikram",
                    "Source IP blacklisted for 24h.",
                    utc_now(),
                    utc_now(),
                ),
            ]
            cursor.executemany("""
                INSERT OR IGNORE INTO incidents (id, title, severity, status, source_ip, destination_ip, device_id, attack_type, description, assigned_to, remediation_notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, incidents)

            conn.commit()

    # -----------------------------------------------------
    # CRUD - Devices
    # -----------------------------------------------------

    def list_devices(self, zone: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM devices WHERE 1=1"
            params = []
            if zone:
                query += " AND zone = ?"
                params.append(zone)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC"
            cursor.execute(query, params)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["tags"] = json.loads(d["tags"]) if d["tags"] else []
                results.append(d)
            return results

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
            row = cursor.fetchone()
            if not row:
                return None
            d = dict(row)
            d["tags"] = json.loads(d["tags"]) if d["tags"] else []
            return d

    def create_device(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO devices (id, hostname, ip_address, mac_address, vendor, device_type, zone, status, firmware_version, tags, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["id"],
                data["hostname"],
                data["ip_address"],
                data["mac_address"],
                data["vendor"],
                data["device_type"],
                data["zone"],
                data["status"],
                data["firmware_version"],
                json.dumps(data.get("tags", [])),
                data["created_at"],
                data["updated_at"],
            ))
            conn.commit()
            return self.get_device(data["id"])

    def update_device(self, device_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        existing = self.get_device(device_id)
        if not existing:
            return None

        fields = []
        params = []
        for k, v in updates.items():
            if v is not None and k in ("hostname", "ip_address", "status", "firmware_version", "zone", "tags"):
                fields.append(f"{k} = ?")
                params.append(json.dumps(v) if k == "tags" else v)

        if not fields:
            return existing

        fields.append("updated_at = ?")
        params.append(utc_now())
        params.append(device_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id = ?", params)
            conn.commit()
            return self.get_device(device_id)

    def delete_device(self, device_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            conn.commit()
            return cursor.rowcount > 0

    # -----------------------------------------------------
    # CRUD - Incidents
    # -----------------------------------------------------

    def list_incidents(self, severity: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM incidents WHERE 1=1"
            params = []
            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())
            if status:
                query += " AND status = ?"
                params.append(status.upper())
            query += " ORDER BY created_at DESC"
            cursor.execute(query, params)
            return [dict(r) for r in cursor.fetchall()]

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def create_incident(self, data: Dict[str, Any]) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incidents (id, title, severity, status, source_ip, destination_ip, device_id, attack_type, description, assigned_to, remediation_notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["id"],
                data["title"],
                data["severity"],
                data["status"],
                data["source_ip"],
                data["destination_ip"],
                data.get("device_id"),
                data["attack_type"],
                data["description"],
                data.get("assigned_to"),
                data.get("remediation_notes"),
                data["created_at"],
                data["updated_at"],
            ))
            conn.commit()
            return self.get_incident(data["id"])

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        existing = self.get_incident(incident_id)
        if not existing:
            return None

        fields = []
        params = []
        for k, v in updates.items():
            if v is not None and k in ("title", "severity", "status", "assigned_to", "remediation_notes"):
                fields.append(f"{k} = ?")
                params.append(v)

        if not fields:
            return existing

        fields.append("updated_at = ?")
        params.append(utc_now())
        params.append(incident_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?", params)
            conn.commit()
            return self.get_incident(incident_id)

    def delete_incident(self, incident_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            conn.commit()
            return cursor.rowcount > 0

    # -----------------------------------------------------
    # Users & Audit
    # -----------------------------------------------------

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, full_name, email, role, is_active, created_at FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def record_audit(self, actor: str, action: str, resource_type: str, resource_id: str, status: str, details: Dict[str, Any]):
        audit_id = f"AUDIT-{abs(hash(actor + action + utc_now())) % 1000000:06d}"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (id, timestamp, actor, action, resource_type, resource_id, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                audit_id,
                utc_now(),
                actor,
                action,
                resource_type,
                resource_id,
                status,
                json.dumps(details),
            ))
            conn.commit()


# Singleton Instance
db = DatabaseManager()
