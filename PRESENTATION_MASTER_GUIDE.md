# 🏆 Smart India Hackathon (SIH) — Master Presentation Guide
**Problem Statement ID:** 26156  
**Problem Statement Title:** Universal Log Pre-processing Framework (ULPF)  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  

---

## 👥 Assigned Presentation Flow & Speaker Breakdown

| Order | Speaker | Topic | Core Focus & Responsibilities | Speech Script Link |
|:---:|:---|:---|:---|:---|
| **1** | **D Akash Dora** *(dora)* | **Introduction** | NTRO Problem Statement (PS ID: 26156), hybrid/multi-cloud log explosion, enterprise pain points, format fragmentation, team welcome. | [`SPEECH_1_D_AKASH_DORA.md`](file:///d:/projects/sih-26/SPEECH_1_D_AKASH_DORA.md) |
| **2** | **Aryan Vishwakarma** *(aryan)* | **Solution** | ULPF overview, core design philosophy, 100% lossless preservation guarantee, canonical event taxonomy, plug-and-play onboarding, business value. | [`SPEECH_2_ARYAN_VISHWAKARMA.md`](file:///d:/projects/sih-26/SPEECH_2_ARYAN_VISHWAKARMA.md) |
| **3** | **Swayam Wakodikar** *(swayam)* | **Architecture** | End-to-end blueprint, dual-pipeline decoupled architecture, Fluent Bit edge agent, Kafka shock-absorber buffer, ClickHouse MergeTree + Neo4j Graph DB. | [`SPEECH_3_SWAYAM_WAKODIKAR.md`](file:///d:/projects/sih-26/SPEECH_3_SWAYAM_WAKODIKAR.md) |
| **4** | **Krish Patel** *(krish)* | **ML Services** | Two-stage threat evaluation (deterministic triage gate + deep ML), 384-dimensional vector embeddings, Kaggle-trained multi-class classifiers, risk formula: $0.65 \times \text{Anomaly} + 0.35 \times \text{Confidence}$. | [`SPEECH_4_KRISH_PATEL.md`](file:///d:/projects/sih-26/SPEECH_4_KRISH_PATEL.md) |
| **5** | **Rushikesh Munde** *(rushi)* | **Metrics & Logs** | Multi-format log normalization (RFC 5424/3164, CEF, LEEF, Windows CSV, Apache, JSON), OpenTelemetry `/v1/traces` & `/v1/metrics`, live telemetry UI dashboard. | [`SPEECH_5_RUSHIKESH_MUNDE.md`](file:///d:/projects/sih-26/SPEECH_5_RUSHIKESH_MUNDE.md) |
| **6** | **Aadya Priyam** *(aadya)* | **Security & Conclusion** | Recursive PII sanitization (`***REDACTED***`), 100% air-gapped readiness (zero cloud API leakage), Kubernetes Helm packaging, SIEM CEF alert dispatching, benchmarks & Q&A opening. | [`SPEECH_6_AADYA_PRIYAM.md`](file:///d:/projects/sih-26/SPEECH_6_AADYA_PRIYAM.md) |

---

## ⏱️ Recommended Time Schedule (Total: 8 - 10 Minutes)
- **D Akash Dora (Intro):** 1.5 Mins
- **Aryan Vishwakarma (Solution):** 1.5 Mins
- **Swayam Wakodikar (Architecture):** 1.5 Mins
- **Krish Patel (ML Services):** 1.5 Mins
- **Rushikesh Munde (Metrics & Logs):** 1.5 Mins
- **Aadya Priyam (Security & Closing):** 1.5 Mins
- **Judges Q&A:** 3 – 5 Mins

---

## 🔄 Verbal Transition Hand-offs

1. **Dora ➡️ Aryan:**
   > *"I will now invite Aryan to present our proposed solution and key capabilities."*
2. **Aryan ➡️ Swayam:**
   > *"I will now invite Swayam to present our end-to-end system architecture and data pipeline."*
3. **Swayam ➡️ Krish:**
   > *"I now invite Krish to dive deep into our Machine Learning models and Threat Detection Engine."*
4. **Krish ➡️ Rushikesh:**
   > *"I will now invite Rushikesh to cover our multi-format log parsing engine and real-time OpenTelemetry metrics."*
5. **Rushikesh ➡️ Aadya:**
   > *"I will now invite Aadya to explain our data security mechanisms, PII redaction, and air-gapped defense compliance."*
6. **Aadya ➡️ Judges (Closing):**
   > *"Thank you very much. Our team is now ready for your questions and evaluation."*

---

## ❓ Rapid-Fire Q&A Responder Matrix

| Question from Judges | Assigned Primary Responder | Technical Answer Anchor |
|:---|:---|:---|
| *"How do you handle log format diversity without writing new parsers every time?"* | **Rushikesh Munde** | Modular regex dispatch in Fluent Bit + extensible dictionary dispatch with heuristic fallbacks in `normalizer.py`. |
| *"How do you guarantee 100% lossless forensic retention?"* | **Aryan Vishwakarma** | Normalized fields populate structured columns, while the original raw log is stored verbatim in `raw_message` with full UUID/timestamp correlation. |
| *"Why use both ClickHouse and Neo4j?"* | **Swayam Wakodikar** | ClickHouse is columnar (optimal for high-throughput log aggregation & SIEM queries); Neo4j is a graph database (optimal for distributed trace spans, parent-child DAGs, and attack paths). |
| *"Does your ML threat detector work in an air-gapped defense network?"* | **Aadya Priyam** | Yes. All models, vector tokenizers, and inference routines run locally on-premise without external cloud APIs. |
| *"What happens if millions of logs arrive at once?"* | **Swayam Wakodikar** | Kafka buffers spikes, while our consumer flushes micro-batches (100 records / 5s timeout) directly to ClickHouse MergeTree storage. |
| *"How does your ML avoid slowing down the pipeline?"* | **Krish Patel** | Two-stage evaluation: deterministic heuristic triage filters benign traffic in <1ms, invoking deep ML classification only for suspicious events. |
| *"How do you protect sensitive credentials in logs?"* | **Aadya Priyam** | Recursive `_sanitize_data` masks sensitive keys (passwords, tokens, API keys) with `***REDACTED***` prior to storage. |
