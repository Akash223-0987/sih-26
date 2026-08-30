"""
Pydantic Schemas for Request Validation and Response Serialization.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------
# Common & Health Schemas
# ---------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    telemetry_enabled: bool


class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[dict] = None


# ---------------------------------------------------------
# Device Schemas (CRUD)
# ---------------------------------------------------------

class DeviceBase(BaseModel):
    hostname: str = Field(..., example="fw-perimeter-01.corp.local")
    ip_address: str = Field(..., example="192.168.10.1")
    mac_address: str = Field(..., example="00:50:56:a3:1b:22")
    vendor: str = Field(..., example="PaloAlto")
    device_type: str = Field(..., example="firewall")
    zone: str = Field(default="dmz", example="dmz")
    status: str = Field(default="active", example="active")
    firmware_version: str = Field(default="10.2.3", example="10.2.3")
    tags: List[str] = Field(default_factory=list, example=["edge", "primary", "pci-dss"])


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    status: Optional[str] = None
    firmware_version: Optional[str] = None
    zone: Optional[str] = None
    tags: Optional[List[str]] = None


class DeviceResponse(DeviceBase):
    id: str
    created_at: str
    updated_at: str


# ---------------------------------------------------------
# Security Incident Schemas (CRUD)
# ---------------------------------------------------------

class IncidentBase(BaseModel):
    title: str = Field(..., example="Multiple SSH Authentication Failures")
    severity: str = Field(..., example="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL
    status: str = Field(default="OPEN", example="OPEN")
    source_ip: str = Field(..., example="203.0.113.45")
    destination_ip: str = Field(..., example="192.168.10.15")
    device_id: Optional[str] = Field(None, example="DEV-1001")
    attack_type: str = Field(..., example="BruteForce")
    description: str = Field(..., example="Detected 120 failed SSH attempts in 60 seconds.")
    assigned_to: Optional[str] = Field(None, example="analyst_vikram")
    remediation_notes: Optional[str] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    remediation_notes: Optional[str] = None


class IncidentResponse(IncidentBase):
    id: str
    created_at: str
    updated_at: str


# ---------------------------------------------------------
# Auth & User Schemas
# ---------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., example="admin")
    password: str = Field(..., example="SecOps#2026!Pass")


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict
    expires_in: int = 3600


class UserResponse(BaseModel):
    username: str
    full_name: str
    email: str
    role: str
    is_active: bool
    created_at: str


# ---------------------------------------------------------
# Diagnostics / Test Schemas
# ---------------------------------------------------------

class ChaosSimulationRequest(BaseModel):
    error_type: str = Field(..., example="database_timeout")
    severity_trigger: str = Field(default="CRITICAL", example="CRITICAL")
    simulate_packet_loss: bool = False
    custom_message: Optional[str] = None
