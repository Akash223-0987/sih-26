# Grafana Dashboard Setup Guide

> **Step-by-step instructions to set up the ULPF Security Operations dashboard with Grafana.**

---

## Prerequisites

- Docker >= 24 and Docker Compose v2
- The Metracer / ULPF repository cloned locally

---

## Step 1 — Stop Everything and Clean Up

Stop all running containers, remove volumes, and clean up stale networks:

```bash
docker stop $(docker ps -q) 2>$null
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml down -v --remove-orphans
docker network prune -f
```

---

## Step 2 — Start the Stack

Launch the full pipeline with Grafana:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml up --build -d
```

This starts the following services:
| Service | Purpose |
|:---|:---|
| log-generator | Emits all 7 log formats every 2 seconds |
| fluent-bit | Collects and forwards logs to Kafka |
| kafka | Message broker |
| log-consumer | Normalizes logs and writes to ClickHouse |
| clickhouse | Columnar analytics database |
| neo4j | Graph database for threat correlation |
| ml-analyzer | ML-based threat classification |
| grafana | Dashboard and visualization |

---

## Step 3 — Wait 2 Minutes

Kafka needs time to start and the pipeline needs to initialize. Wait **at least 2 minutes** before checking.

---

## Step 4 — Verify Data is Flowing

Run this command to check if logs are being ingested into ClickHouse:

```bash
docker exec clickhouse-ulpf clickhouse-client --query "SELECT count() FROM ulpf.logs_normalized"
```

You should see a number **greater than 0** (e.g., `44282`).

If it's still `0`, check the log-consumer for errors:

```bash
docker logs infra-log-consumer-1 --tail 10
```

---

## Step 5 — Open Grafana

Open your browser and go to:

**http://localhost:3000**

---

## Step 6 — Login

Enter the following credentials:

- **Username:** `admin`
- **Password:** `admin`

When prompted to change the password, click **"Skip"** (bottom of the page) for development use.

---

## Step 7 — View the Dashboard

The **ULPF Security Operations** dashboard loads automatically as the home page.

If it doesn't, navigate to:
**Dashboards** (left sidebar) → **ULPF Security Operations**

---

## Dashboard Panels

The dashboard includes 12 panels across 4 rows:

### Row 1 — Key Metrics
| Panel | Description |
|:---|:---|
| Total Events (24h) | Count of all normalized log events |
| Active Alerts (24h) | Count of security alerts |
| Unique Source IPs | Distinct source IPs seen |
| Log Formats Ingested | Number of different log source types |

### Row 2 — Ingestion & Severity
| Panel | Description |
|:---|:---|
| Log Ingestion Rate | Events per minute over time (line chart) |
| Events by Severity | Donut chart with color-coded severity levels |

### Row 3 — Source Analysis
| Panel | Description |
|:---|:---|
| Top 10 Source IPs | Horizontal bar chart of noisiest IPs |
| Log Source Distribution | Donut chart of log format breakdown |
| Alerts by Severity | Bar gauge showing alert counts by severity |

### Row 4 — Alert Details
| Panel | Description |
|:---|:---|
| Alert Timeline | Stacked bar chart of alerts over time |
| Recent Alerts | Table with timestamp, rule, severity, IP, user |
| Top Alerted IPs | Bar chart of IPs with the most alerts |

---

## Enabling Alert Panels

The alert panels (Alert Timeline, Alerts by Severity, Recent Alerts, Top Alerted IPs) require the **threat detection pipeline**. To enable them, run with the architecture overlay:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.architecture.yml -f infra/docker-compose.grafana.yml up --build -d
```

This adds threat detection, anomaly detection, and notification services that score logs and write alerts to the `ulpf.alerts` table.

---

## Useful Commands

| Task | Command |
|:---|:---|
| Check log count | `docker exec clickhouse-ulpf clickhouse-client --query "SELECT count() FROM ulpf.logs_normalized"` |
| Check alert count | `docker exec clickhouse-ulpf clickhouse-client --query "SELECT count() FROM ulpf.alerts"` |
| View consumer logs | `docker logs infra-log-consumer-1 --tail 20` |
| View threat detection logs | `docker logs infra-threat-detection-1 --tail 20` |
| Stop everything | `docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml down -v` |
| Restart a single service | `docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml restart <service-name>` |

---

## Troubleshooting

### Grafana login not working
The `grafana-data` volume may have a cached password. Clean up and restart:
```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml down -v
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml up --build -d
```

### Port already in use
Old containers are holding the port. Stop all containers and prune networks:
```bash
docker stop $(docker ps -q) 2>$null
docker network prune -f
```

### ClickHouse count is 0 after 2 minutes
Check if the log-consumer can resolve Kafka:
```bash
docker logs infra-log-consumer-1 --tail 10
```
If you see `Failed to resolve 'kafka:9092'`, clean up orphan containers and restart:
```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml down -v --remove-orphans
docker network prune -f
docker compose -f infra/docker-compose.yml -f infra/docker-compose.grafana.yml up --build -d
```

### Kafka "Message timed out" warnings
This is normal during the first 30–60 seconds after startup. Fluent Bit retries automatically once Kafka is ready.
