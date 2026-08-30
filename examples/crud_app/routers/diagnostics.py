"""
Router for Diagnostics, Chaos Testing, and High-Volume Telemetry Verification.
"""

import time
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status

from pytrace import logger, update_request_attribute
from examples.crud_app.database import db
from examples.crud_app.schemas import APIResponse, ChaosSimulationRequest

router = APIRouter(prefix="/api/v1/diagnostics", tags=["Diagnostics & Chaos Testing"])


@router.get("/stats", response_model=APIResponse, summary="Get system data counts")
def get_system_stats():
    """Retrieve operational telemetry statistics."""
    devices = db.list_devices()
    incidents = db.list_incidents()

    logger.info(
        "Diagnostics health check performed",
        event_type="diagnostics_stats",
        total_devices=len(devices),
        total_incidents=len(incidents),
    )

    return APIResponse(
        success=True,
        message="System telemetry stats retrieved",
        data={
            "total_devices": len(devices),
            "total_incidents": len(incidents),
            "active_devices": sum(1 for d in devices if d["status"] == "active"),
            "critical_incidents": sum(1 for i in incidents if i["severity"] == "CRITICAL"),
        },
    )


@router.post("/simulate-error", summary="Simulate an unhandled 500 error for forensic stacktrace verification")
def simulate_error(
    error_type: str = Query(
        "db_connection_refused",
        description="Type of error: db_connection_refused, memory_exhaustion, auth_service_timeout, corrupted_packet"
    )
):
    """
    Intentionally throws an unhandled exception.
    PyTrace intercepts this and logs full exception class, traceback, and context to logs/application.log.
    """
    update_request_attribute("chaos_test", True)
    update_request_attribute("simulated_error_type", error_type)

    logger.warn(f"Simulating intentional failure mode: {error_type}", chaos_mode=True)

    if error_type == "db_connection_refused":
        raise ConnectionRefusedError("Database replica at 10.100.1.50:5432 failed health probe: Connection refused")
    elif error_type == "memory_exhaustion":
        raise MemoryError("Allocating buffer for 10M packet capture frames failed: Out of memory")
    elif error_type == "corrupted_packet":
        raise ValueError("Malformed Ethernet frame header detected: 0xDEADBEEF checksum mismatch")
    else:
        raise RuntimeError(f"Unhandled runtime fault: {error_type}")


@router.post("/burst-logs", response_model=APIResponse, summary="Emit rapid batch of structured logs to test ingest throughput")
def burst_logs(
    count: int = Query(25, ge=1, le=500, description="Number of log records to emit rapidly"),
    level: str = Query("info", description="Log level: info, warn, error"),
):
    """Emit a high-speed batch of structured logs to test Fluent Bit buffer & Kafka pipeline."""
    start_time = time.perf_counter()

    for i in range(count):
        msg = f"Throughput test telemetry event {i + 1}/{count}"
        if level == "error":
            logger.error(msg, batch_index=i + 1, batch_total=count, test_id="burst-benchmark")
        elif level == "warn":
            logger.warn(msg, batch_index=i + 1, batch_total=count, test_id="burst-benchmark")
        else:
            logger.info(msg, batch_index=i + 1, batch_total=count, test_id="burst-benchmark")

    elapsed_ms = (time.perf_counter() - start_time) * 1000.0

    return APIResponse(
        success=True,
        message=f"Successfully generated {count} {level.upper()} telemetry log records in {elapsed_ms:.2f}ms",
        data={"count": count, "level": level, "elapsed_ms": elapsed_ms},
    )


@router.post("/chaos", response_model=APIResponse, summary="Simulate custom chaos scenarios")
def simulate_chaos(payload: ChaosSimulationRequest):
    """Trigger custom chaos security telemetry."""
    logger.warn(
        "Chaos scenario executed",
        event_type="chaos_scenario_injected",
        error_type=payload.error_type,
        severity_trigger=payload.severity_trigger,
        packet_loss=payload.simulate_packet_loss,
        custom_note=payload.custom_message,
    )
    return APIResponse(
        success=True,
        message=f"Chaos simulation '{payload.error_type}' executed with severity {payload.severity_trigger}",
        data=payload.model_dump(),
    )
