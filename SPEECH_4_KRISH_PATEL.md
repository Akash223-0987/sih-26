# 🎤 SIH Presentation Script — Speaker 4: Krish Patel
**Topic:** Machine Learning Services, Anomaly Detection & Threat Intelligence  
**Target Speaking Time:** ~1.5 - 2 Minutes

---

## 🎯 High-Level Objective
Present the AI/ML intelligence engine of ULPF: explain the two-stage evaluation pipeline (deterministic triage + ML inference), vector embeddings, multi-class threat classifiers, and the mathematical risk scoring formula.

---

## 🗣️ Exact Spoken Script (Word-for-Word Guide)

### 1. Two-Stage ML Architecture & Deterministic Triage (0:00 - 0:40)
> *"Thank you, Swayam.*  
> *I am **Krish Patel**, and I will explain the AI/ML intelligence services powering ULPF.*
>
> *In production environments with over 100,000 events per second, running heavy neural networks on every single benign log line causes catastrophic latency.  
> To solve this, we designed a **Two-Stage Threat Evaluation Engine**:*
> - **Stage 1: Deterministic Heuristic Triage Gate:** Incoming normalized events are quickly checked by a lightweight rule gate for high-severity tags, suspicious command signatures (e.g., `failed password`, `nmap`, `denied`, `port scan`), or system anomalies (CPU utilization ≥ 90%, error rate ≥ 10%, latency ≥ 1000ms).
> - *Benign events pass through instantly to storage with zero ML latency.*
> - *Suspicious signals are immediately elevated to **Stage 2: Deep ML Analysis**."*

---

### 2. Feature Extraction, Embeddings & Threat Classifiers (0:40 - 1:20)
> *(Explaining the ML Models & Feature Engineering)*  
> *"Inside our **ML-Analyzer** service:*
> - **384-Dimensional Semantic Embeddings:** We transform raw and normalized log structures into dense vector representations that capture semantic attack patterns regardless of minor syntax variations.
> - **Multi-Class Threat Classification:** Using models trained on extensive cybersecurity and Kaggle intrusion datasets, our classifier identifies specific attack vectors, including **SSH/Auth Brute Force**, **Port Reconnaissance / Nmap Scans**, **DDoS Flooding**, **Malware Beacons**, and **Privilege Escalation**.
> - **Statistical Anomaly Engine:** In parallel, an unsupervised anomaly detector tracks statistical deviations from normal operational baselines, applying an adaptive decay rate to adapt to evolving traffic patterns."*

---

### 3. Unified Risk Scoring Formula (1:20 - 1:45)
> *(Explaining the Risk Score Equation)*  
> *"To ensure SOC analysts receive high-precision alerts without alarm fatigue, we compute a composite **Risk Score**:*
> 
> $$\text{Risk Score} = \min\left(1.0,\; 0.65 \times \text{Anomaly Score} + 0.35 \times \text{Threat Confidence}\right)$$
>
> - *If the combined Risk Score crosses our threshold of **0.70**, an automated high-severity incident is declared.*
> - *Inference executes in **under 15 milliseconds**, making ULPF fully capable of real-time inline threat mitigation.*
>
> *Now, **Rushikesh** will explain our multi-format log normalization and live OpenTelemetry metrics.*"

---

## 📌 Key Technical Points to Emphasize
- **Two-Stage Evaluation (Fast Triage Gate + Deep ML Inference)**
- **384-Dimensional Vector Embeddings**
- **Pre-Trained Threat Classifiers (Brute Force, Port Scan, DDoS, Malware)**
- **Risk Score Formula: $0.65 \times \text{Anomaly} + 0.35 \times \text{Confidence}$ (Threshold: 0.70)**

## 🔄 Verbal Transition Cue
➡️ Hand over to **Rushikesh Munde** by saying:  
*"I will now invite Rushikesh to cover our multi-format log parsing engine and real-time OpenTelemetry metrics."*
