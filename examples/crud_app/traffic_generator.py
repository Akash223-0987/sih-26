"""
Automated Real-Time Traffic & Attack Simulation Generator.

Sends continuous or one-shot synthetic HTTP requests across all CRUD endpoints:
- Devices: GET (list), POST (create), PUT (update), DELETE (decommission)
- Incidents: GET (list/filter), POST (alert trigger), PUT (state change), DELETE (purge)
- Auth: Login successes and failed brute-force attempts
- Diagnostics: 500 error injections, burst benchmarks, chaos events

Usage:
    python -m examples.crud_app.traffic_generator --interval 1.0 --duration 60
    python -m examples.crud_app.traffic_generator --mode once
    python -m examples.crud_app.traffic_generator --mode chaos
"""

import argparse
import random
import sys
import time
import urllib.error
import urllib.request
import json
from typing import Dict, Any, Optional

BASE_URL = "http://127.0.0.1:8000"

VENDORS = ["PaloAlto", "Cisco", "Fortinet", "Juniper", "CheckPoint", "Sophos"]
DEVICE_TYPES = ["firewall", "router", "switch", "ips", "gateway", "waf"]
ZONES = ["dmz", "internal", "external", "core", "pci-zone"]
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
ATTACK_TYPES = ["PortScan", "BruteForce", "SQLInjection", "DDoS", "MalwareBeacon", "PrivilegeEscalation", "XSS"]


def http_request(method: str, path: str, data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> tuple[int, Any]:
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            status_code = response.status
            res_body = response.read().decode("utf-8")
            try:
                parsed = json.loads(res_body)
            except Exception:
                parsed = res_body
            return status_code, parsed
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(err_body)
        except Exception:
            parsed = err_body
        return e.code, parsed
    except Exception as e:
        return 0, str(e)


def random_ip() -> str:
    return f"{random.randint(10, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def simulate_device_crud() -> Optional[str]:
    # 1. CREATE Device (POST)
    vendor = random.choice(VENDORS)
    dev_type = random.choice(DEVICE_TYPES)
    hostname = f"{dev_type}-{vendor.lower()}-{random.randint(10, 99)}.corp.local"
    ip = random_ip()

    status_code, created = http_request(
        "POST",
        "/api/v1/devices",
        data={
            "hostname": hostname,
            "ip_address": ip,
            "mac_address": f"00:50:56:{random.randint(10,99):02x}:{random.randint(10,99):02x}:{random.randint(10,99):02x}",
            "vendor": vendor,
            "device_type": dev_type,
            "zone": random.choice(ZONES),
            "status": "active",
            "firmware_version": f"{random.randint(1,15)}.{random.randint(0,9)}.{random.randint(0,5)}",
            "tags": ["automated-traffic", vendor.lower()],
        },
        headers={"X-Actor-User": "secops_automation"},
    )
    print(f"  [DEVICE CREATE] {status_code} -> ID: {created.get('id') if isinstance(created, dict) else 'error'}")
    if status_code != 201 or not isinstance(created, dict):
        return None

    device_id = created["id"]

    # 2. READ Device (GET)
    s_code, _ = http_request("GET", f"/api/v1/devices/{device_id}")
    print(f"  [DEVICE GET]    {s_code} -> {device_id}")

    # 3. UPDATE Device (PUT)
    s_code, _ = http_request(
        "PUT",
        f"/api/v1/devices/{device_id}",
        data={"status": "maintenance", "firmware_version": "12.0.1-patch"},
    )
    print(f"  [DEVICE UPDATE] {s_code} -> Set status=maintenance")

    # 4. Sometimes DELETE Device (DELETE)
    if random.random() < 0.4:
        s_code, _ = http_request("DELETE", f"/api/v1/devices/{device_id}")
        print(f"  [DEVICE DELETE] {s_code} -> Decommissioned {device_id}")
        return None

    return device_id


def simulate_incident_crud(device_id: Optional[str] = None):
    # 1. CREATE Incident (POST)
    severity = random.choice(SEVERITIES)
    attack = random.choice(ATTACK_TYPES)
    src_ip = random_ip()
    dst_ip = random_ip()

    status_code, created = http_request(
        "POST",
        "/api/v1/incidents",
        data={
            "title": f"{attack} signature matched on ingress port",
            "severity": severity,
            "status": "OPEN",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "device_id": device_id,
            "attack_type": attack,
            "description": f"Automated sensor triggered alert on {src_ip} -> {dst_ip}",
            "assigned_to": "analyst_vikram" if severity in ("HIGH", "CRITICAL") else None,
        },
        headers={"X-Source-System": "automated_generator"},
    )
    print(f"  [INCIDENT POST] {status_code} -> [{severity}] {attack} (ID: {created.get('id') if isinstance(created, dict) else 'error'})")
    if status_code != 201 or not isinstance(created, dict):
        return

    incident_id = created["id"]

    # 2. UPDATE Incident (PUT)
    new_status = random.choice(["INVESTIGATING", "CONTAINED", "RESOLVED"])
    s_code, _ = http_request(
        "PUT",
        f"/api/v1/incidents/{incident_id}",
        data={"status": new_status, "remediation_notes": f"Applied automated containment filter at {new_status}"},
    )
    print(f"  [INCIDENT PUT]  {s_code} -> Transitioned {incident_id} to {new_status}")


def simulate_auth():
    # Successful login
    s_code, _ = http_request("POST", "/api/v1/auth/login", data={"username": "admin", "password": "SecOps#2026!Pass"})
    print(f"  [AUTH SUCCESS]  {s_code} -> Logged in as admin")

    # Failed / Brute-force attempt
    s_code, _ = http_request("POST", "/api/v1/auth/login", data={"username": "root", "password": "wrong_password_999"})
    print(f"  [AUTH FAILURE]  {s_code} -> Expected 401 for bad login attempt")


def simulate_diagnostics():
    # Simulate error
    err_type = random.choice(["db_connection_refused", "memory_exhaustion", "corrupted_packet"])
    s_code, _ = http_request("POST", f"/api/v1/diagnostics/simulate-error?error_type={err_type}")
    print(f"  [CHAOS 500]     {s_code} -> Simulated {err_type}")

    # Burst logs
    s_code, res = http_request("POST", "/api/v1/diagnostics/burst-logs?count=10&level=info")
    print(f"  [BURST LOGS]    {s_code} -> Burst 10 telemetry events")


def run_cycle(iteration: int):
    print(f"\n--- [Cycle #{iteration}] Generating Telemetry Events ---")
    # Health probe
    http_request("GET", "/health")

    # Device CRUD
    dev_id = simulate_device_crud()

    # Incident CRUD
    simulate_incident_crud(dev_id)

    # Auth event
    simulate_auth()

    # Diagnostics / Chaos event occasionally
    if iteration % 3 == 0:
        simulate_diagnostics()

    # Device & Incident listings (GET)
    http_request("GET", "/api/v1/devices?zone=dmz")
    http_request("GET", "/api/v1/incidents?severity=CRITICAL")
    print(f"--- [Cycle #{iteration}] Completed. Logs appended to logs/application.log ---\n")


def main():
    parser = argparse.ArgumentParser(description="Real-Time Traffic & Telemetry Log Generator for ULPF")
    parser.add_argument("--mode", choices=["loop", "once", "chaos"], default="loop", help="Execution mode")
    parser.add_argument("--interval", type=float, default=1.5, help="Interval between cycles in seconds (default: 1.5s)")
    parser.add_argument("--duration", type=int, default=0, help="Total seconds to run (0 for infinite loop)")
    args = parser.parse_args()

    print(f"Connecting to FastAPI app at {BASE_URL}...")
    s_code, res = http_request("GET", "/health")
    if s_code != 200:
        print(f"❌ Error: Cannot connect to FastAPI app at {BASE_URL} (Status: {s_code}).")
        print("Please start the FastAPI app first with:")
        print("    python -m examples.crud_app.main")
        print("or:")
        print("    uvicorn examples.crud_app.main:app --port 8000")
        sys.exit(1)

    print(f"Connected to {res.get('service', 'API')} ({res.get('status', 'OK')}). Starting log generation...\n")

    if args.mode == "once":
        run_cycle(1)
        return

    if args.mode == "chaos":
        print("Running Chaos & Error Ingestion Telemetry Test...")
        for _ in range(5):
            simulate_diagnostics()
            time.sleep(0.5)
        return

    iteration = 1
    start_time = time.time()
    try:
        while True:
            run_cycle(iteration)
            iteration += 1
            if args.duration > 0 and (time.time() - start_time) >= args.duration:
                print(f"Duration {args.duration}s reached. Stopping traffic generator.")
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nTraffic generator stopped by user.")


if __name__ == "__main__":
    main()
