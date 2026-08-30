"""
API Routers for FastAPI CRUD Application.
"""

from examples.crud_app.routers.devices import router as devices_router
from examples.crud_app.routers.incidents import router as incidents_router
from examples.crud_app.routers.auth import router as auth_router
from examples.crud_app.routers.diagnostics import router as diagnostics_router

__all__ = ["devices_router", "incidents_router", "auth_router", "diagnostics_router"]
