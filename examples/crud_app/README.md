# Enterprise Perimeter & Threat Management FastAPI Service (CRUD Testbed)

> **SIH Problem Statement 26156: Universal Log Pre-processing Framework (ULPF)**  
> **Organization:** National Technical Research Organisation (NTRO)  
> **Module:** Real-Time Application & Security Telemetry Log Producer

---

## 📌 Purpose

This multi-file FastAPI application acts as an enterprise service and perimeter device management hub. It provides **complete CRUD operations** (Create, Read, Update, Delete) across perimeter devices, security incidents, user authentications, and diagnostics.

It is instrumented with the **PyTrace Telemetry SDK** to emit rich, structured, lossless JSON logs with W3C distributed tracing context into `logs/application.log`. These logs are ingested in real time by the **ULPF pipeline** (Fluent Bit -> Kafka -> Normalizer -> ClickHouse & Neo4j).

---

## 🗂️ Project Structure

```
examples/crud_app/
├── __init__.py               # Package descriptor
├── config.py                 # App settings, environment vars, log paths
├── database.py               # Thread-safe SQLite database & auto-seeding
├── models.py                 # Dataclass domain models (Devices, Incidents, Users, Audits)
├── schemas.py                # Pydantic request/response validation schemas
├── services.py               # CRUD business logic + PyTrace telemetry enrichment
├── main.py                   # FastAPI app entrypoint, PyTrace instrumentation, routes
├── traffic_generator.py      # Automated real-time traffic & attack simulation script
├── README.md                 # Setup, verification, and deployment documentation
└── routers/
    ├── __init__.py           # Router aggregation
    ├── devices.py            # Perimeter Devices CRUD (GET, POST, PUT, DELETE)
    ├── incidents.py          # Security Incidents / Alerts CRUD (GET, POST, PUT, DELETE)
    ├── auth.py               # User Login, Logout & Audit Trail
    └── diagnostics.py        # Error simulation (500s), burst benchmarks, chaos events
```

---

## 🚀 How to Run the Application & Faculty Presentation

You can run `examples/crud_app/main.py` in multiple ways during your presentation:

### Option 1: Interactive Faculty Presentation Menu (Recommended for Demos)
Run without any arguments to see the interactive launcher menu:
```bash
python examples/crud_app/main.py
```
This lets you select on-the-spot:
1. **Start FastAPI CRUD Server** (Swagger UI at `http://127.0.0.1:8000/docs`)
2. **Run SIH 4-Phase Demo Orchestrator** (Full terminal presentation with ML & Neo4j graph)
3. **Run Live Integrated Telemetry Demo** (Executes live CRUD transactions + normalizes live logs)
4. **Run Automated Traffic Generator** (Continuous synthetic traffic)

---

### Option 2: Direct CLI Flags

```bash
# 1. Run the Full 4-Phase SIH Presentation Orchestrator directly:
python examples/crud_app/main.py --demo

# 2. Run the Live Integrated CRUD + Normalization demo:
python examples/crud_app/main.py --live

# 3. Start the FastAPI Web Server with Swagger Docs:
python examples/crud_app/main.py --server

# 4. Automated Walkthrough (for screen recording / timed transitions):
python examples/crud_app/main.py --auto --delay 3

# 5. Fast Execution (for quick evaluation / CI):
python examples/crud_app/main.py --fast
```

Once running:
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

## 📡 Generating Real-Time Telemetry Logs

In a separate terminal, run the automated traffic simulator to send continuous CRUD operations, logins, and chaos events:

```bash
# Run continuous traffic generator (every 1.5s)
python -m examples.crud_app.traffic_generator

# Run a single one-shot test cycle
python -m examples.crud_app.traffic_generator --mode once

# Run chaos & unhandled 500 error injection test
python -m examples.crud_app.traffic_generator --mode chaos
```

### Inspect Generated Logs

All logs are written in real-time to `logs/application.log`:

```bash
# View live log stream (PowerShell)
Get-Content logs/application.log -Wait -Tail 20

# View live log stream (Linux / Git Bash)
tail -f logs/application.log
```

---

## 🌐 Endpoints Overview

| Method | Endpoint | Description | Telemetry Generated |
|---|---|---|---|
| `GET` | `/` | Service root probe | Health status & version |
| `GET` | `/health` | Liveness check | Container readiness probe |
| `GET` | `/api/v1/devices` | List perimeter devices | Inventory query log |
| `GET` | `/api/v1/devices/{id}` | Get device details | Device lookup & attributes |
| `POST` | `/api/v1/devices` | Create/register device | Provisioning audit event |
| `PUT` | `/api/v1/devices/{id}` | Update device settings | Config change audit event |
| `DELETE` | `/api/v1/devices/{id}` | Decommission device | Decommission audit log |
| `GET` | `/api/v1/incidents` | List security incidents | SOC triage query log |
| `GET` | `/api/v1/incidents/{id}` | Get incident details | Threat incident lookup |
| `POST` | `/api/v1/incidents` | Create incident / alert | Threat alert (HIGH/CRITICAL) |
| `PUT` | `/api/v1/incidents/{id}` | Update incident state | Incident state transition log |
| `DELETE` | `/api/v1/incidents/{id}` | Delete incident | Incident purge audit log |
| `POST` | `/api/v1/auth/login` | User login attempt | Login success or brute force alert |
| `POST` | `/api/v1/auth/logout` | User logout | Session audit trail |
| `POST` | `/api/v1/diagnostics/simulate-error` | Throws 500 exception | Full stacktrace forensic log |
| `POST` | `/api/v1/diagnostics/burst-logs` | High-frequency burst | Pipeline throughput benchmark |

---

## 💡 "Do I Need to Deploy This or Not?"

### Short Answer:
**For testing, SIH evaluation, and demonstration purposes: NO, you do NOT need to deploy this to an external cloud or public server.**

### Detailed Breakdown:

1. **For Evaluation & SIH Presentation (Local/On-Premises):**
   - The entire ULPF architecture is designed to run locally using Docker Compose (`infra/docker-compose.yml`) or directly on your machine.
   - Running the FastAPI app locally (`http://127.0.0.1:8000`) and tailing `logs/application.log` demonstrates the exact real-time pipeline behavior: log creation -> Fluent Bit parsing -> Kafka streaming -> ULPF normalization -> ClickHouse & Neo4j.
   - NTRO guidelines explicitly state: *"The solution shall be deployable in an air-gapped network"* and *"packaged in a container for making it platform independent."* Running locally or in local Docker containers directly satisfies the **air-gapped requirement** without external internet dependencies.

2. **When WOULD you deploy it?**
   - **Multi-Node Testbed / Cloud Staging**: If you want a live public URL for judges to hit from their own browsers during the demo, you can deploy this FastAPI app to a cloud VM or container service (e.g. AWS EC2, GCP Cloud Run, Azure App Service).
   - **Enterprise Integration**: In a real production deployment at an organization like NTRO, this FastAPI app represents microservices and perimeter control planes running inside the organization's private data centers, writing logs to Fluent Bit sidecars or syslog relays.
