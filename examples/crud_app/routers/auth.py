"""
Router for Authentication, Identity, and Audit operations.
"""

from fastapi import APIRouter, HTTPException, Request, status, Header
from typing import Optional

from examples.crud_app.schemas import LoginRequest, LoginResponse, UserResponse, APIResponse
from examples.crud_app.services import AuthService
from examples.crud_app.database import db

router = APIRouter(prefix="/api/v1/auth", tags=["Identity & Access Control"])


@router.post("/login", response_model=LoginResponse, summary="User authentication")
def login(payload: LoginRequest, request: Request):
    """Authenticate user and log security audit event."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user = AuthService.authenticate(payload.username, payload.password, client_ip=client_ip)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password credentials.",
        )

    return LoginResponse(
        access_token=f"jwt_mock_token_{user['username']}_2026",
        token_type="bearer",
        user=user,
        expires_in=3600,
    )


@router.post("/logout", response_model=APIResponse, summary="User logout audit event")
def logout(
    x_actor_user: Optional[str] = Header(default="admin", description="Logged in username"),
):
    """Log operator logout audit trail."""
    db.record_audit(
        actor=x_actor_user,
        action="LOGOUT",
        resource_type="auth",
        resource_id=x_actor_user,
        status="SUCCESS",
        details={},
    )
    return APIResponse(success=True, message=f"User '{x_actor_user}' successfully logged out.")


@router.get("/users/{username}", response_model=UserResponse, summary="Get user account information")
def get_user_account(username: str):
    """Inspect user profile and role privileges."""
    user = db.get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' was not found.",
        )
    return user
