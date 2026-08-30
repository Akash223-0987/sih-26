"""
Router for Perimeter Network Devices (CRUD).
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status, Header

from examples.crud_app.schemas import DeviceCreate, DeviceResponse, DeviceUpdate, APIResponse
from examples.crud_app.services import DeviceService

router = APIRouter(prefix="/api/v1/devices", tags=["Perimeter Devices (CRUD)"])


@router.get("", response_model=List[DeviceResponse], summary="List all perimeter network devices")
def list_devices(
    zone: Optional[str] = Query(None, description="Filter by network zone (e.g., dmz, internal, core)"),
    status: Optional[str] = Query(None, description="Filter by operational status (e.g., active, maintenance)"),
):
    """Retrieve list of perimeter network devices with optional filtering."""
    return DeviceService.get_all(zone=zone, status=status)


@router.get("/{device_id}", response_model=DeviceResponse, summary="Get perimeter device details by ID")
def get_device(device_id: str):
    """Retrieve details for a single network perimeter device."""
    device = DeviceService.get_by_id(device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Perimeter device with ID '{device_id}' was not found.",
        )
    return device


@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED, summary="Register a new perimeter device")
def create_device(
    payload: DeviceCreate,
    x_actor_user: Optional[str] = Header(default="secops_admin", description="Identity of the operator"),
):
    """Register a new firewall, router, or IDS appliance into the inventory."""
    return DeviceService.create(payload.model_dump(), actor=x_actor_user)


@router.put("/{device_id}", response_model=DeviceResponse, summary="Update device configuration or status")
def update_device(
    device_id: str,
    payload: DeviceUpdate,
    x_actor_user: Optional[str] = Header(default="secops_admin", description="Identity of the operator"),
):
    """Update settings, firmware, or operational status for an existing device."""
    updated = DeviceService.update(device_id, payload.model_dump(exclude_unset=True), actor=x_actor_user)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' not found for update.",
        )
    return updated


@router.delete("/{device_id}", response_model=APIResponse, summary="Decommission/delete a device")
def delete_device(
    device_id: str,
    x_actor_user: Optional[str] = Header(default="secops_admin", description="Identity of the operator"),
):
    """Decommission and remove a perimeter device from the topology."""
    success = DeviceService.delete(device_id, actor=x_actor_user)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{device_id}' could not be deleted because it does not exist.",
        )
    return APIResponse(
        success=True,
        message=f"Device '{device_id}' successfully decommissioned.",
        data={"device_id": device_id},
    )
