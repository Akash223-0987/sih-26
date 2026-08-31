# 🎤 SIH Presentation Script — Speaker 3: Swayam Wakodikar
**Topic:** End-to-End System Architecture & Data Pipeline  
**Target Speaking Time:** ~1.5 - 2 Minutes

---

## 🎯 High-Level Objective
Walk through the architectural blueprint of ULPF: explain the dual-pipeline design, the roles of Fluent Bit, Apache Kafka, ClickHouse, and Neo4j, and how the decoupled services interact seamlessly at scale.

---

## 🗣️ Exact Spoken Script (Word-for-Word Guide)

### 1. Architecture Overview & Dual-Pipeline Strategy (0:00 - 0:40)
> *"Thank you, Aryan.*  
> *I am **Swayam Wakodikar**, and I will walk you through the architectural blueprint of ULPF.*
>
> *(Pointing to Architecture Slide / Diagram)*  
> *To handle massive enterprise scale without bottlenecks, we engineered a **Dual-Pipeline, Decoupled Microservices Architecture**:*
> - **Branch 1: High-Volume Perimeter & System Logs Pipeline**  
>   *(Optimized for high-throughput batching, columnar compression, and SIEM search).*
> - **Branch 2: OpenTelemetry Distributed Metrics & Traces Pipeline**  
>   *(Optimized for graph topology, latency tracking, and root-cause lineage).*
>
> *Let us follow the lifecycle of an event through each layer."*

---

### 2. Deep Dive: Layer-by-Layer Components (0:40 - 1:20)
> *"1. **Edge Collection Layer (Fluent Bit & PyTrace SDK):**  
> Logs generated from network perimeters, routers, and application servers are ingested by **Fluent Bit** and tagged with their identified `log_format` via regex parsers and `record_modifier` filters.
>
> *2. **Streaming & Ingestion Buffer (Apache Kafka):**  
> All streams publish to Apache Kafka on the `enterprise-logs` topic. Kafka acts as our distributed shock absorber, ensuring zero dropped logs even under heavy DDoS or traffic spikes.
>
> *3. **Normalization & Dual Storage Layer:**  
> - Our **Log Consumer** reads Kafka batches, normalizes records into our canonical schema, and executes high-performance micro-batch writes to **ClickHouse** with a partitioned `MergeTree` engine.
> - Concurrently, our **Telemetry Ingestor** processes OpenTelemetry metrics and distributed spans, building a live entity graph in **Neo4j** (`Service -> Trace -> Span`).
>
> *4. **Intelligence & Decision Layer:**  
> Normalized ClickHouse logs and Neo4j telemetry graph context converge at the **Threat Detection Decision Point**, which routes suspicious signals to the ML-Analyzer."*

---

### 3. Why This Architecture Wins (1:20 - 1:45)
> *"By segregating structured analytical queries into **ClickHouse** and contextual attack paths into **Neo4j**, we eliminate database locking and achieve both sub-millisecond search times and instant graph correlation.
>
> *Now, I will hand over to **Krish**, who will explain our Machine Learning and Threat Detection services in detail."*

---

## 📌 Key Technical Points to Emphasize
- **Dual-Pipeline Strategy (Logs in ClickHouse + Telemetry in Neo4j)**
- **Edge Collection: Fluent Bit + PyTrace SDK**
- **Kafka Decoupling & Ingestion Buffer**
- **ClickHouse `MergeTree` + Neo4j Graph Correlation**

## 🔄 Verbal Transition Cue
➡️ Hand over to **Krish Patel** by saying:  
*"I now invite Krish to dive deep into our Machine Learning models and Threat Detection Engine."*
