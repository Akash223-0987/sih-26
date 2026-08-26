from __future__ import annotations

import asyncio
import json
import logging
import traceback
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List, Optional, Protocol

from pytrace.ml import ULPFPipeline

logger = logging.getLogger("ulpf.pipeline")


class Message(Protocol):
    value: bytes


@dataclass
class StreamConfig:
    batch_size: int = 256
    linger_ms: int = 10
    alert_confidence: float = 0.85
    alert_anomaly_score: float = 0.90


class PipelineService:
    """Async batch processor with injected Kafka-compatible consume/publish hooks."""

    def __init__(self, pipeline: Optional[ULPFPipeline] = None, config: Optional[StreamConfig] = None):
        self.pipeline = pipeline or ULPFPipeline()
        self.config = config or StreamConfig()
        self._stopping = False

    @staticmethod
    def decode(value: bytes) -> Any:
        text = value.decode("utf-8")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def process_message(self, value: bytes) -> tuple[str, dict[str, Any]]:
        raw_text = value.decode("utf-8", errors="replace")
        try:
            processed = self.pipeline.process(self.decode(value))
            inference = processed.inference
            normalized = inference.normalized.model_dump(mode="json")
            normalized["ml_processed"] = True
            alert = inference.threat_label != "Benign" and inference.threat_confidence >= self.config.alert_confidence
            alert = alert or inference.anomaly_score >= self.config.alert_anomaly_score
            return "ok", {"normalized": normalized, "alert": alert, "alert_payload": processed.routes.siem}
        except Exception as exc:
            return "dlq", {
                "ml_processed": False,
                "raw_payload": raw_text,
                "error": str(exc),
                "error_traceback": traceback.format_exc(),
            }

    async def process_batch(self, values: List[bytes], publish: Callable[[str, dict[str, Any]], Awaitable[None]], commit: Callable[[], Awaitable[None]]) -> None:
        for value in values:
            status, payload = self.process_message(value)
            if status == "dlq":
                await publish("logs.dlq", payload)
                continue
            await publish("logs.normalized", payload["normalized"])
            await publish("ulpf.clickhouse", payload["normalized"])
            await publish("ulpf.neo4j", payload["normalized"])
            if payload["alert"]:
                await publish("alerts.security", payload["alert_payload"])
        await commit()

    async def run(self, consume: Callable[[], Awaitable[Optional[bytes]]], publish: Callable[[str, dict[str, Any]], Awaitable[None]], commit: Callable[[], Awaitable[None]]) -> None:
        batch: List[bytes] = []
        while not self._stopping:
            value = await consume()
            if value is not None:
                batch.append(value)
            if batch and (len(batch) >= self.config.batch_size or value is None):
                await self.process_batch(batch, publish, commit)
                batch.clear()
            if value is None:
                await asyncio.sleep(self.config.linger_ms / 1000)

    async def stop(self) -> None:
        self._stopping = True
