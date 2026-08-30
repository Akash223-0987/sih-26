# ULPF Architecture - NTRO PS 26156

## Purpose

ULPF converts perimeter-device logs and OpenTelemetry metrics/traces into a lossless, common security event model. It preserves every source record, enriches it with parsed fields and trace context, and provides a single path to analytics, correlation, ML scoring, and alerting. All components are containerized and use internal endpoints only, so the deployment remains suitable for an air-gapped network.

## Processing flow

```text
Logs --> Fluent Bit --> Kafka --> Consumer/Normalizer --> ClickHouse ----> ML Model
                                          |                    |
                                          +--> Threat Detection +-- suspicious --> ML API --> Alert --> Notification Service

Metrics + Traces --> OpenTelemetry --> Telemetry Ingestor --> Neo4j ----> ML Model
                                          |                    |
                                          +--> Threat Detection +-- suspicious --> ML API --> Alert --> Notification Service
```

1. **Logs / Fluent Bit / Kafka.** Fluent Bit tails or receives Syslog, JSON, CEF, LEEF, Apache, Windows CSV and other device logs. Parser tags are published to the Kafka `enterprise-logs` topic, which isolates producers from consumers and enables horizontal scaling.
2. **Consumer and canonical schema.** The log consumer detects the source format and produces one normalized event. `raw_message` is retained unchanged; parsed fields are stored in `extra_attributes`, providing forensic traceability. The log branch writes **only to ClickHouse**.
3. **Metrics and traces.** Devices and applications send OTLP/HTTP data to the telemetry ingestor on port 4318. The telemetry branch writes **only to Neo4j**, creating service-to-span and service-to-metric relationships for correlation.
4. **ML service and threat detection.** ClickHouse logs and Neo4j metrics/traces are the ML model inputs. After each successful database write, both branches also fan out to threat detection. It performs lightweight rule triage first; only suspicious evidence triggers the ML API. A non-benign result above the configured risk threshold becomes an alert.
5. **Notifications.** Alerts are handed to the local notification service. It exposes a dashboard-friendly alert history and can forward to an internally hosted webhook (SOC, SIEM, email relay) only when explicitly configured.

## Deployment and security

Start the core pipeline plus the diagram services:

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.architecture.yml up --build
```

The additional service endpoints are telemetry `:4318`, threat detection `:8002`, notifications `:8003`, and anomaly detection `:8004`. No cloud dependency is required at runtime. Configure retention through the ClickHouse TTL, restrict exposed ports to the SOC network, and place credentials/webhook URLs in a local secrets mechanism rather than source control.
