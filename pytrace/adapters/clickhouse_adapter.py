from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional

from pytrace.ml.models import InferenceResult


class ClickHouseAdapter:
    """Buffered ClickHouse sink; the writer is injectable for offline tests."""

    def __init__(self, writer: Optional[Callable[[List[Dict[str, Any]]], Awaitable[None]]] = None, batch_size: int = 1000, flush_interval: float = 2.0):
        self.writer = writer
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer: List[Dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._task: Optional[asyncio.Task[None]] = None

    @staticmethod
    def format_record(result: InferenceResult) -> Dict[str, Any]:
        log = result.normalized
        return {
            "timestamp": log.timestamp,
            "raw_log_sha256": log.raw_log_sha256,
            "threat_label": result.threat_label,
            "threat_confidence": float(result.threat_confidence),
            "anomaly_score": float(result.anomaly_score),
            "embedding": [float(value) for value in result.embedding],
            "src_ip": log.src_ip or "",
            "dest_ip": log.dst_ip or "",
            "dest_port": log.dst_port,
            "raw_message": log.raw_log,
            "unmapped_properties": log.unmapped_properties,
        }

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._periodic_flush())

    async def add(self, result: InferenceResult) -> None:
        async with self._lock:
            self.buffer.append(self.format_record(result))
            should_flush = len(self.buffer) >= self.batch_size
        if should_flush:
            await self.flush()

    async def flush(self) -> None:
        async with self._lock:
            batch, self.buffer = self.buffer, []
        if batch and self.writer is not None:
            await self.writer(batch)

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        await self.flush()

    async def _periodic_flush(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            await self.flush()
