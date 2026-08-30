"""
Main FastAPI Application Entrypoint with PyTrace Universal Telemetry Instrumentation.

Designed for SIH Problem Statement 26156 (Universal Log Pre-processing Framework).
Emits rich, structured, lossless application and security audit logs to logs/application.log
for downstream ingestion by Fluent Bit, Kafka, Normalizer, ClickHouse, and Neo4j.
"""

import sys
from pathlib import Path

# Ensure root workspace is on Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pytrace import PyTrace, logger, update_request_attribute
from examples.crud_app.config import settings
from examples.crud_app.schemas import HealthResponse
from examples.crud_app.routers import (
    devices_router,
    incidents_router,
    auth_router,
    diagnostics_router,
)

# ---------------------------------------------------------
# FastAPI App Creation
# ---------------------------------------------------------

app = FastAPI(
    title=settings.app_name,
    description=(
        "Universal Log Pre-processing Framework (ULPF) Testbed Application. "
        "Provides complete CRUD operations for perimeter devices, security incidents, "
        "and auth audit logging, instrumented with PyTrace for real-time lossless telemetry."
    ),
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ---------------------------------------------------------
# PyTrace Telemetry Auto-Instrumentation
# ---------------------------------------------------------
# Automatically intercepts HTTP requests, records method, path, status, latency,
# captures trace context (trace_id, span_id, request_id), and exports to logs/application.log
PyTrace(
    app,
    service_name=settings.service_name,
    environment=settings.environment,
)

# ---------------------------------------------------------
# CORS Middleware
# ---------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Global Exception Handlers
# ---------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global catch-all for uncaught exceptions.
    PyTrace captures the exception traceback and emits it to logs/application.log.
    """
    logger.error(
        f"Unhandled application exception in {request.method} {request.url.path}: {str(exc)}",
        error_class=exc.__class__.__name__,
        endpoint=request.url.path,
        method=request.method,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred. Forensic telemetry has been recorded.",
            "detail": str(exc),
            "path": request.url.path,
        },
    )


# ---------------------------------------------------------
# Root & Health Endpoints
# ---------------------------------------------------------

@app.get("/", response_model=HealthResponse, summary="Root Service Health Endpoint")
def root():
    """Service status and telemetry metadata."""
    update_request_attribute("endpoint_type", "root_probe")
    logger.info("Service root ping received", component="gateway", health="healthy")
    return HealthResponse(
        status="operational",
        service=settings.service_name,
        version=settings.app_version,
        environment=settings.environment,
        telemetry_enabled=True,
    )


@app.get("/health", response_model=HealthResponse, summary="Liveness / Readiness Probe")
def health_check():
    """Liveness probe for container orchestration."""
    return HealthResponse(
        status="healthy",
        service=settings.service_name,
        version=settings.app_version,
        environment=settings.environment,
        telemetry_enabled=True,
    )


# ---------------------------------------------------------
# Mount Feature Routers
# ---------------------------------------------------------

app.include_router(devices_router)
app.include_router(incidents_router)
app.include_router(auth_router)
app.include_router(diagnostics_router)


# ---------------------------------------------------------
# Direct Execution Runner
# ---------------------------------------------------------

def start():
    print("=" * 70)
    print(f"🚀 Starting {settings.app_name}")
    print(f"📡 Host: http://{settings.host}:{settings.port}")
    print(f"📖 Swagger Docs: http://{settings.host}:{settings.port}/docs")
    print(f"📝 Telemetry logs written to: {settings.log_file_path}")
    print("=" * 70)
    uvicorn.run(
        "examples.crud_app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    start()
