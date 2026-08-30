# ULPF ML Analyzer

The analyzer normalizes raw or structured perimeter logs, preserves the exact source with a SHA-256 forensic hash, computes a deterministic CPU embedding, scores structural anomalies, classifies common threat families, and emits downstream payloads.

## Local API

```bash
cd services/ML-Analyzer
uvicorn main:app --reload
```

The hyphenated service directory is intended for direct script/container execution. From the repository root, run the container with `docker compose -f infra/docker-compose.yml up ml-analyzer`.

- `GET /health` returns service readiness.
- `POST /v1/infer` accepts `{ "log": "..." }` or `{ "log": { "message": "..." } }`.

Set `ENABLE_KAFKA=true` to consume `logs.raw`. The worker publishes normalized records to `logs.normalized`, high-risk SIEM records to `alerts.security`, and routing payloads to `ulpf.clickhouse` and `ulpf.neo4j`.

The default hashing vectorizer and online detector are air-gapped fallbacks. Their interfaces are deliberately isolated so an ONNX, FastEmbed, Isolation Forest, or XGBoost adapter can be introduced without changing the Kafka or API contracts.