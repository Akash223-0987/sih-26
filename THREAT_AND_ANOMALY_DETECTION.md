# Threat & Anomaly Detection Guide

> **PyTrace / ULPF Security Operations**  
> Clear, non-technical explanation of how threat detection, anomaly scoring, and automated incident response work in this platform.

---

## 1. What is Threat & Anomaly Detection?

The main objective of **PyTrace / ULPF** is to protect enterprise applications by detecting cyber threats and operational anomalies in real time.

Instead of relying only on static rules, the system uses a **Dual-Engine Approach**:

```
                       Incoming Security Logs & Telemetry
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    ▼                                     ▼
      Supervised ML Classifier               Unsupervised Anomaly Engine
     (Detects KNOWN Attack Types)          (Detects UNKNOWN / Zero-Day Outliers)
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                                       ▼
                       Automated Risk Tiering & Response
```

---

## 2. The Dual Detection Engines

### Engine A: Supervised ML Threat Classifier
Identifies **known cyber attack patterns** using a LightGBM machine learning model trained on network metrics and graph relationships.

* **5 Threat Categories:**
  1. **`Benign`**: Normal operational application traffic.
  2. **`Brute Force`**: Repeated authentication failures, password spraying, or SSH/RDP guessing attempts.
  3. **`Lateral Movement`**: An attacker moving sideways across internal servers (SMB/RDP/SSH traversals).
  4. **`Exfiltration`**: Unusually large outbound data transfers or suspicious long-lived data sessions.
  5. **`Port Scan`**: Rapid probing of multiple ports or network nodes to find vulnerabilities.

### Engine B: Unsupervised Hybrid Anomaly Engine
Detects **unknown zero-day anomalies** and metric spikes that don't match any pre-trained attack pattern.

* **Isolation Forest**: Identifies unusual combinations of metrics that stand out from normal baseline traffic.
* **Statistical Z-Score Analysis**: Monitors key indicators (e.g., sudden jump in outbound bytes, abnormal trace call depth, or high failure rates) and flags metrics exceeding safe baseline thresholds.

---

## 3. How Threats Are Rated (Risk Tiers)

Every detected log or event is assigned a **Risk Level**:

| Risk Level | Trigger Condition | Meaning |
| :--- | :--- | :--- |
| **`CRITICAL`** | High confidence ML threat ($\ge 80\%$) or extreme anomaly score | Active severe attack needing immediate response |
| **`HIGH`** | Medium-to-high ML threat confidence ($55\% \text{ to } 79\%$) | Suspicious attack activity requiring SecOps action |
| **`MEDIUM`** | Uncertain prediction or unusual metric anomaly ($\ge 70\%$) | Event flagged for context enrichment & monitoring |
| **`LOW`** | Normal benign traffic | Safe event stored for standard analytical records |

---

## 4. What Happens After a Threat is Flagged? (4-Stage Action Pipeline)

When a threat or anomaly is detected, the platform triggers an automated 4-stage pipeline:

### Step 1: Risk Assessment & Labeling
* Computes the confidence score and assigns the risk tier (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`).

### Step 2: Instant Alert & Notification Dispatch
* **Gmail Email Alerts (`EmailNotificationHandler`)**: Dispatches rich HTML security threat notifications directly to administrator inboxes via Gmail SMTP.
* **SIEM CEF Logs (`SIEMCEFHandler`)**: Formats alerts into Common Event Format (CEF) strings for enterprise SIEM ingestion.
* **Console Audit Logs (`ConsoleNotificationHandler`)**: Logs structured warning alerts to operational system streams.

### Step 3: Forensic Correlation (Graph Database)
* Updates graph nodes and relationships in **Neo4j** to connect the IP address, user account, and trace spans.
* Helps security analysts visually trace the attack route and identify affected infrastructure.

### Step 4: Automated Mitigation & Storage
* **Critical / High Threats**: Triggers firewall blocking (IP isolation) or revokes compromised user authentication tokens.
* **Storage**: Losslessly saves the original log and normalized attributes in **ClickHouse** for forensic audit compliance.

---

## 5. How to Run and Test

You can test the entire detection pipeline by running the included scenario simulation script:

```bash
python scripts/demo_threat_detection.py
```

### Running the Test Suite
To verify all threat classifier and anomaly engine unit tests:

```bash
python -m pytest tests/test_anomaly_detector.py tests/test_redesigned_ml_service.py
```
