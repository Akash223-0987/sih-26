# 🎤 SIH Presentation Script — Speaker 5: Rushikesh Munde
**Topic:** Multi-Format Log Normalization & OpenTelemetry Metrics  
**Target Speaking Time:** ~1.5 - 2 Minutes

---

## 🎯 High-Level Objective
Showcase the technical mechanics of log normalization across 7+ enterprise formats and explain how OpenTelemetry distributed metrics and traces are collected, parsed, and visualized in real time on our interactive telemetry dashboard.

---

## 🗣️ Exact Spoken Script (Word-for-Word Guide)

### 1. Universal Log Parsing & Normalization in Action (0:00 - 0:40)
> *"Thank you, Krish.*  
> *I am **Rushikesh Munde**, and I will explain how ULPF normalizes heterogeneous log streams and processes OpenTelemetry metrics and traces in real time.*
>
> *In our `normalizer.py` engine, we implement dedicated parsers for every major industry log format:*
> 1. **Syslog RFC 5424 & RFC 3164:** PRI-to-severity bitmask decoding, extracting authenticating user and IP from freeform messages.
> 2. **CEF (Common Event Format):** Parsing space-separated key-value pairs from Palo Alto, Fortinet, and Check Point perimeter firewalls.
> 3. **LEEF (Log Event Extended Format):** Tab-delimited attribute extraction from IBM QRadar.
> 4. **Windows Event Log (CSV/NXLog):** Extracting Windows Event IDs (like 4625 failed logins and 4672 privilege escalation).
> 5. **Apache/Nginx Combined Access Logs:** HTTP verbs, URI paths, and status code to severity mapping.
> 6. **PyTrace Canonical JSON:** Direct structured microservice telemetry."*

---

### 2. OpenTelemetry Metrics & Distributed Traces (0:40 - 1:20)
> *(Explaining OpenTelemetry Ingestion & Telemetry UI)*  
> *"In parallel to logs, our **Telemetry Ingestor** (`services/Metric-Traces service`) exposes standard OpenTelemetry HTTP/gRPC endpoints at `/v1/traces` and `/v1/metrics`:*
> - **Trace Spans:** We parse `resourceSpans`, extracting `traceId`, `spanId`, `parentSpanId`, service names, latency duration, and HTTP status codes. Spans exceeding 1000ms are automatically flagged as latency anomalies.
> - **System Metrics:** We ingest gauges, sums, and histograms measuring CPU utilization, memory pressure, network I/O, packet rates, and socket error counts.
> - **Interactive Telemetry Dashboard:** Our built-in web dashboard provides real-time visibility into active perimeter devices, live packet rates, active connections, and anomaly feeds with zero external monitoring overhead."*

---

### 3. Log-to-Trace Correlation (1:20 - 1:45)
> *"Because both logs in ClickHouse and traces in Neo4j share standardized timestamps, IP addresses, and `trace_id` correlation handles, security analysts can jump from a high-severity firewall log directly to the exact distributed microservice trace that triggered it.
>
> *Now, **Aadya** will present our data security, PII sanitization, air-gapped readiness, and defense compliance."*

---

## 📌 Key Technical Points to Emphasize
- **Format Normalization (Syslog RFC 5424/3164, CEF, LEEF, Windows CSV, Apache, JSON)**
- **OpenTelemetry `/v1/traces` & `/v1/metrics` Ingestor**
- **Trace Latency & Resource Utilization Anomaly Detection**
- **Log-to-Trace Correlation via Shared `trace_id` & Canonical Fields**

## 🔄 Verbal Transition Cue
➡️ Hand over to **Aadya Priyam** by saying:  
*"I will now invite Aadya to explain our data security mechanisms, PII redaction, and air-gapped defense compliance."*
