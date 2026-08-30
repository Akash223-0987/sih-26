"""
Router for Security Incidents and Threat Alerts (CRUD).
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status, Header

from examples.crud_app.schemas import (
    IncidentCreate,
    IncidentResponse,
    IncidentUpdate,
    APIResponse,
)
from examples.crud_app.services import IncidentService

router = APIRouter(prefix="/api/v1/incidents", tags=["Security Incidents (CRUD)"])


@router.get("", response_model=List[IncidentResponse], summary="List security incidents")
def list_incidents(
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL"),
    incident_status: Optional[str] = Query(None, alias="status", description="Filter by status: OPEN, INVESTIGATING, RESOLVED, CLOSED"),
):
    """Retrieve security incidents and threat alerts."""
    return IncidentService.get_all(severity=severity, status=incident_status)


@router.get("/{incident_id}", response_model=IncidentResponse, summary="Get security incident by ID")
def get_incident(incident_id: str):
    """Retrieve details for a specific incident."""
    incident = IncidentService.get_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return incident


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED, summary="Log a new security incident")
def create_incident(
    payload: IncidentCreate,
    x_source_system: Optional[str] = Header(default="perimeter_ids", description="Ingestion source name"),
):
    """Create a new incident record (triggers real-time threat telemetry event)."""
    return IncidentService.create(payload.model_dump(), actor=x_source_system)


@router.put("/{incident_id}", response_model=IncidentResponse, summary="Update security incident status or assignment")
def update_incident(
    incident_id: str,
    payload: IncidentUpdate,
    x_actor_user: Optional[str] = Header(default="analyst_vikram", description="SOC Analyst ID"),
):
    """Update investigation state, remediation notes, or severity."""
    updated = IncidentService.update(incident_id, payload.model_dump(exclude_unset=True), actor=x_actor_user)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return updated


@router.delete("/{incident_id}", response_model=APIResponse, summary="Delete an incident")
def delete_incident(
    incident_id: str,
    x_actor_user: Optional[str] = Header(default="secops_admin", description="SOC Administrator"),
):
    """Remove an incident from active registry."""
    success = IncidentService.delete(incident_id, actor=x_actor_user)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return APIResponse(
        success=True,
        message=f"Incident '{incident_id}' deleted successfully.",
        data={"incident_id": incident_id},
    )
