import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from typing import Any, Dict

import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from pytrace.ml import ULPFPipeline

logger = logging.getLogger("ulpf.ml-analyzer")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
pipeline = ULPFPipeline(
    dimensions=int(os.getenv("EMBEDDING_DIMENSIONS", "384")),
    anomaly_threshold=float(os.getenv("ANOMALY_THRESHOLD", "0.72")),
    model_dir=os.getenv("LOCAL_MODEL_DIR"),
    anomaly_decay=float(os.getenv("ANOMALY_DECAY", "0.05")),
    temperature=float(os.getenv("CLASSIFIER_TEMPERATURE", "1.0")),
)
_stop_event = threading.Event()
_worker_thread: threading.Thread | None = None
_kafka_consumer: Any = None
_kafka_producer: Any = None


class InferenceRequest(BaseModel):
    log: Any


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "ulpf-ml-analyzer"}


@app.post("/v1/infer")
def infer(request: InferenceRequest) -> Dict[str, Any]:
    try:
        return pipeline.process(request.log).model_dump(mode="json")
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def kafka_worker() -> None:
    global _kafka_consumer, _kafka_producer
    try:
        from confluent_kafka import Consumer, Producer
    except ImportError:
        logger.warning("confluent-kafka is unavailable; Kafka worker disabled")
        return
    broker = os.getenv("KAFKA_BROKER", "kafka:9092")
    consumer = Consumer({"bootstrap.servers": broker, "group.id": os.getenv("KAFKA_GROUP", "ulpf-ml-analyzer"), "auto.offset.reset": "earliest"})
    producer = Producer({"bootstrap.servers": broker})
    _kafka_consumer = consumer
    _kafka_producer = producer
    consumer.subscribe([os.getenv("KAFKA_INPUT_TOPIC", "logs.raw")])
    logger.info("Kafka worker subscribed to logs.raw")
    try:
        while not _stop_event.is_set():
            message = consumer.poll(1.0)
            if message is None:
                continue
            if message.error():
                logger.error("Kafka consumer error: %s", message.error())
                continue
            try:
                raw = json.loads(message.value().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raw = message.value().decode("utf-8", errors="replace")
            processed = pipeline.process(raw)
            producer.produce("logs.normalized", json.dumps(processed.inference.normalized.model_dump(mode="json")))
            if processed.inference.risk_score >= float(os.getenv("ALERT_RISK_THRESHOLD", "0.7")):
                producer.produce("alerts.security", json.dumps(processed.routes.siem))
            producer.produce("ulpf.clickhouse", json.dumps(processed.routes.clickhouse))
            producer.produce("ulpf.neo4j", json.dumps(processed.routes.neo4j))
            producer.poll(0)
    finally:
        consumer.close()
        producer.flush(10)
        _kafka_consumer = None
        _kafka_producer = None


def start_kafka_worker() -> None:
    global _worker_thread
    if os.getenv("ENABLE_KAFKA", "false").lower() in {"1", "true", "yes"}:
        _stop_event.clear()
        _worker_thread = threading.Thread(target=kafka_worker, name="kafka-worker", daemon=True)
        _worker_thread.start()


def stop_kafka_worker() -> None:
    _stop_event.set()
    if _kafka_consumer is not None:
        _kafka_consumer.wakeup()
    if _worker_thread is not None:
        _worker_thread.join(timeout=5)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await asyncio.to_thread(pipeline.warmup)
    start_kafka_worker()
    try:
        yield
    finally:
        await asyncio.to_thread(stop_kafka_worker)


app = FastAPI(title="ULPF ML Inference", version="1.0.0", lifespan=lifespan)
