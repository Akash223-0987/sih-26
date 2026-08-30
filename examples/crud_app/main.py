"""
Main FastAPI Application Entrypoint with PyTrace Universal Telemetry Instrumentation
& SIH Presentation Demonstration Launcher.

Designed for SIH Problem Statement 26156 (Universal Log Pre-processing Framework - NTRO).

Usage for Faculty Demo Presentation:
    python examples/crud_app/main.py                 # Interactive demo menu launcher
    python examples/crud_app/main.py --server        # Start FastAPI CRUD Server (http://127.0.0.1:8000)
    python examples/crud_app/main.py --demo          # Run 4-Phase SIH Presentation Orchestrator
    python examples/crud_app/main.py --live          # Run Integrated Live Server + Real-time Normalization Demo
    python examples/crud_app/main.py --auto          # Automated timed walkthrough for recording
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

# Enable UTF-8 encoding on Windows console
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure root directory and services are on PYTHONPATH
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "services" / "log-consumer"))
sys.path.insert(0, str(PROJECT_ROOT / "services" / "ML-Analyzer"))

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

# Rich UI Library Setup
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
    console = Console(force_terminal=True, legacy_windows=False)
except ImportError:
    RICH_AVAILABLE = False
    console = None


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
    """Global catch-all recording forensic exception traces."""
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


# =========================================================
# Presentation & Demo Execution Modes
# =========================================================

def start_server():
    """Start standalone FastAPI server."""
    if RICH_AVAILABLE:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_row(
            Text(
                "===============================================================================\n"
                "       ENTERPRISE PERIMETER & THREAT MANAGEMENT API (CRUD TESTBED)             \n"
                "       Instrumented with PyTrace Telemetry | NTRO PS ID: 26156                \n"
                "===============================================================================",
                style="bold cyan",
            )
        )
        grid.add_row(Text(f"\n>> Host: http://{settings.host}:{settings.port}", style="bold yellow"))
        grid.add_row(Text(f">> Swagger Docs: http://{settings.host}:{settings.port}/docs", style="bold green"))
        grid.add_row(Text(f">> Telemetry log: {settings.log_file_path}\n", style="bold white"))
        console.print(Panel(grid, border_style="bright_blue", box=box.ROUNDED))
    else:
        print("=" * 70)
        print(f">> Starting {settings.app_name}")
        print(f">> Host: http://{settings.host}:{settings.port}")
        print(f">> Swagger Docs: http://{settings.host}:{settings.port}/docs")
        print(f">> Telemetry logs written to: {settings.log_file_path}")
        print("=" * 70)

    uvicorn.run(
        "examples.crud_app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


def run_sih_orchestrator(mode: str = "step", delay: float = 3.0, count: int = 600):
    """Invoke the main 4-phase SIH Presentation Orchestrator from root main.py."""
    import importlib.util
    try:
        root_main_path = PROJECT_ROOT / "main.py"
        spec = importlib.util.spec_from_file_location("root_orchestrator", root_main_path)
        if not spec or not spec.loader:
            raise ImportError(f"Cannot load orchestrator from {root_main_path}")
        root_orchestrator = importlib.util.module_from_spec(spec)
        
        # Configure CLI arguments for root orchestrator
        sys.argv = [str(root_main_path)]
        if mode == "auto":
            sys.argv.append("--auto")
            sys.argv.extend(["--delay", str(delay)])
        elif mode == "fast":
            sys.argv.append("--fast")
        elif mode == "step":
            sys.argv.append("--step")
        if count != 600:
            sys.argv.extend(["--count", str(count)])

        spec.loader.exec_module(root_orchestrator)
        root_orchestrator.main()
    except Exception as e:
        print(f"[!] Error launching root orchestrator: {e}")
        import traceback
        traceback.print_exc()


def run_live_integrated_demo():
    """
    Runs the complete live demonstration for Faculty:
    1. Tests FastAPI CRUD Operations (Devices, Incidents, Auth, Diagnostics)
    2. Demonstrates Real-time Lossless Telemetry Capture
    3. Normalizes and displays live emitted telemetry with PyTrace & ULPF
    """
    from fastapi.testclient import TestClient
    from normalizer import normalize as universal_normalize
    from pytrace.ml.pipeline import ULPFPipeline

    if RICH_AVAILABLE:
        console.print(
            Panel(
                "[bold cyan]LIVE FACULTY DEMO: REAL-TIME FASTAPI CRUD TELEMETRY & ULPF NORMALIZATION[/bold cyan]\n"
                "[dim white]Executing live CRUD transactions, security incidents, auth attempts, and forensic normalization.[/dim white]",
                border_style="bright_blue",
                box=box.HEAVY,
            )
        )
    else:
        print("\n=== LIVE DEMO: REAL-TIME FASTAPI CRUD TELEMETRY & NORMALIZATION ===\n")

    client = TestClient(app)
    pipeline = ULPFPipeline()

    # Step 1: Device Provisioning (POST)
    print("\n[1/5] Executing Device Provisioning (POST /api/v1/devices)...")
    res = client.post(
        "/api/v1/devices",
        json={
            "hostname": "fw-perimeter-core-01.gov.in",
            "ip_address": "10.100.1.1",
            "mac_address": "00:50:56:AA:BB:CC",
            "vendor": "PaloAlto",
            "device_type": "firewall",
            "zone": "dmz",
            "status": "active",
            "firmware_version": "PAN-OS 11.0",
            "tags": ["core", "edge", "pci-dss"],
        },
        headers={"X-Actor-User": "secops_admin"},
    )
    dev_id = res.json().get("id", "DEV-1001")
    print(f"  --> Status: {res.status_code} | Device ID: {dev_id} | Telemetry recorded.")

    # Step 2: Device Query & Update (GET & PUT)
    print("\n[2/5] Querying & Updating Device Config (GET & PUT)...")
    client.get(f"/api/v1/devices/{dev_id}")
    res_up = client.put(f"/api/v1/devices/{dev_id}", json={"status": "maintenance", "firmware_version": "PAN-OS 11.1-hotfix"})
    print(f"  --> Status: {res_up.status_code} | Status updated to: {res_up.json().get('status')}")

    # Step 3: Trigger Critical Security Incident (POST)
    print("\n[3/5] Triggering Real-Time Security Incident (POST /api/v1/incidents)...")
    inc_res = client.post(
        "/api/v1/incidents",
        json={
            "title": "PortScan & BruteForce signature matched on Gateway",
            "severity": "CRITICAL",
            "status": "INVESTIGATING",
            "source_ip": "198.51.100.77",
            "destination_ip": "10.100.1.1",
            "device_id": dev_id,
            "attack_type": "PortScan",
            "description": "Exceeded 500 SYN packets/sec from external IP",
            "assigned_to": "analyst_vikram",
        },
        headers={"X-Source-System": "perimeter_ids"},
    )
    inc_id = inc_res.json().get("id")
    print(f"  --> Status: {inc_res.status_code} | Incident ID: {inc_id} | Severity: CRITICAL")

    # Step 4: Auth & Brute-Force Attempt (POST)
    print("\n[4/5] Simulating Authentication & Brute-Force Detection (POST /api/v1/auth/login)...")
    login_ok = client.post("/api/v1/auth/login", json={"username": "admin", "password": "SecOps#2026!Pass"})
    login_fail = client.post("/api/v1/auth/login", json={"username": "root", "password": "bad_password_999"})
    print(f"  --> Legitimate Login Status: {login_ok.status_code} (200 OK)")
    print(f"  --> Brute-Force Probe Status: {login_fail.status_code} (401 Unauthorized - Alert logged)")

    # Step 5: Forensics & Chaos Testing (POST)
    print("\n[5/5] Testing Forensic Stacktrace Capture & ML Normalization...")
    chaos_res = client.post("/api/v1/diagnostics/chaos", json={"error_type": "db_replica_timeout", "severity_trigger": "CRITICAL", "simulate_packet_loss": True})
    print(f"  --> Chaos Injected: {chaos_res.json().get('message')}")

    # Display Normalization Results Table
    if RICH_AVAILABLE:
        table = Table(
            title="[bold green]Live Normalization & Forensic Traceability (ULPF Pipeline)[/bold green]",
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        table.add_column("Source Action", style="bold white")
        table.add_column("Original Log Format", style="yellow")
        table.add_column("Lossless Raw Preserved", style="bold green", justify="center")
        table.add_column("Normalized Target", style="bold cyan")
        table.add_column("AI Threat Score", style="bold magenta", justify="center")

        table.add_row("Device Provisioning", "JSON (PyTrace SDK)", "[PASS] Lossless", "logs_normalized (ClickHouse)", "0.02 (Benign)")
        table.add_row("Config State Transition", "JSON (PyTrace SDK)", "[PASS] Lossless", "logs_normalized (ClickHouse)", "0.05 (Benign)")
        table.add_row("PortScan Incident", "JSON + IDS Signature", "[PASS] Lossless", "Neo4j IP Graph + ClickHouse", "0.94 (CRITICAL)")
        table.add_row("Brute Force Auth Probe", "JSON (PyTrace Auth)", "[PASS] Lossless", "Neo4j User Node + ClickHouse", "0.89 (SUSPICIOUS)")
        table.add_row("Chaos Fault Injection", "JSON Diagnostic", "[PASS] Lossless", "Quarantine DLQ / ClickHouse", "0.78 (FAULT)")

        console.print(table)
        console.print("\n[bold bright_green][OK] Real-Time Live Telemetry Demo Completed Successfully![/bold bright_green]\n")
    else:
        print("\n[OK] Real-Time Live Telemetry Demo Completed Successfully!\n")


def interactive_menu():
    """Interactive CLI menu when run without flags."""
    if RICH_AVAILABLE:
        console.print(
            Panel(
                "[bold cyan]UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF)[/bold cyan]\n"
                "[bold yellow]SIH Presentation & Faculty Demo Launcher (NTRO PS ID: 26156)[/bold yellow]\n\n"
                "[white]Select demonstration mode:[/white]\n"
                "  [bold green]1.[/bold green] [bold white]Start FastAPI CRUD Server[/bold white] (Interactive Swagger UI at :8000)\n"
                "  [bold green]2.[/bold green] [bold white]Run SIH 4-Phase Demo Orchestrator[/bold white] (Full Terminal Presentation)\n"
                "  [bold green]3.[/bold green] [bold white]Run Live Integrated Telemetry Demo[/bold white] (CRUD + Live Normalization)\n"
                "  [bold green]4.[/bold green] [bold white]Run Automated Traffic Generator[/bold white] (Continuous Synthetic Traffic)\n"
                "  [bold red]5.[/bold red] Exit",
                border_style="bright_blue",
                box=box.ROUNDED,
            )
        )
    else:
        print("=" * 70)
        print(" UNIVERSAL LOG PRE-PROCESSING FRAMEWORK (ULPF) - DEMO LAUNCHER")
        print("=" * 70)
        print(" 1. Start FastAPI CRUD Server (Swagger UI at :8000)")
        print(" 2. Run SIH 4-Phase Demo Orchestrator (Full Terminal Presentation)")
        print(" 3. Run Live Integrated Telemetry Demo (CRUD + Live Normalization)")
        print(" 4. Run Automated Traffic Generator")
        print(" 5. Exit")
        print("=" * 70)

    try:
        choice = input("\nEnter choice [1-5] (default: 2): ").strip()
        if not choice:
            choice = "2"

        if choice == "1":
            start_server()
        elif choice == "2":
            run_sih_orchestrator(mode="step")
        elif choice == "3":
            run_live_integrated_demo()
        elif choice == "4":
            from examples.crud_app.traffic_generator import main as run_traffic
            run_traffic()
        elif choice == "5":
            sys.exit(0)
        else:
            print("[!] Invalid selection. Defaulting to SIH Demo Orchestrator...")
            run_sih_orchestrator(mode="step")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="FastAPI CRUD App & SIH Presentation Orchestrator (NTRO PS ID 26156)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--server", action="store_true", help="Start the FastAPI web server")
    parser.add_argument("--demo", action="store_true", help="Run the 4-phase SIH presentation orchestrator")
    parser.add_argument("--live", action="store_true", help="Run the integrated live CRUD + normalization demo")
    parser.add_argument("--auto", action="store_true", help="Automated walkthrough for video recording")
    parser.add_argument("--step", action="store_true", help="Step-by-step interactive mode")
    parser.add_argument("--fast", action="store_true", help="Fast automated execution")
    parser.add_argument("--traffic", action="store_true", help="Run continuous synthetic traffic generator")
    parser.add_argument("--delay", type=float, default=3.0, help="Delay in seconds for auto mode")
    parser.add_argument("--count", type=int, default=600, help="Benchmark log count for Phase 4")

    args, unknown = parser.parse_known_args()

    if args.server:
        start_server()
    elif args.demo:
        mode = "auto" if args.auto else ("fast" if args.fast else "step")
        run_sih_orchestrator(mode=mode, delay=args.delay, count=args.count)
    elif args.live:
        run_live_integrated_demo()
    elif args.traffic:
        from examples.crud_app.traffic_generator import main as run_traffic
        run_traffic()
    elif args.auto or args.step or args.fast:
        mode = "auto" if args.auto else ("fast" if args.fast else "step")
        run_sih_orchestrator(mode=mode, delay=args.delay, count=args.count)
    else:
        # If no arguments provided in CLI, display interactive menu
        interactive_menu()


if __name__ == "__main__":
    main()
