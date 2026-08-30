from time import perf_counter
from typing import Any, List

from pytrace.ml.model_engine import ModelEngine
from pytrace.ml.models import InferenceResult, ProcessedLog
from pytrace.ml.parser import normalize_log
from pytrace.ml.routing import route_result


class ULPFPipeline:
    def __init__(
        self,
        dimensions: int = 384,
        anomaly_threshold: float = 0.72,
        model_dir: str | None = None,
        anomaly_decay: float = 0.05,
        temperature: float = 1.0,
    ):
        self.engine = ModelEngine(
            dimensions=dimensions,
            model_dir=model_dir,
            anomaly_threshold=anomaly_threshold,
            anomaly_decay=anomaly_decay,
            temperature=temperature,
        )

    def warmup(self, sample_logs: List[str] | None = None) -> None:
        self.engine.warmup(sample_logs)

    @staticmethod
    def _legacy_label(text: str, predicted_label: str) -> str:
        lowered = text.casefold()
        if any(value in lowered for value in ("failed password", "invalid user", "brute force", "authentication failure")):
            return "Brute Force"
        if any(value in lowered for value in ("nmap", "masscan", "port scan", "port_scan", "syn scan")):
            return "Port Scan"
        return predicted_label

    def process(self, raw: Any) -> ProcessedLog:
        started = perf_counter()
        normalized = normalize_log(raw)
        output = self.engine.infer(normalized.raw_log)
        embedding = output.embedding
        anomaly_score = output.anomaly_score
        label = self._legacy_label(normalized.raw_log, output.predicted_label)
        confidence = output.threat_confidence
        anomaly = anomaly_score >= self.engine.anomaly.threshold
        risk_score = min(1.0, 0.65 * anomaly_score + 0.35 * (1.0 - confidence if label == "Benign" else confidence))
        result = InferenceResult(
            normalized=normalized, embedding=embedding, predicted_label=output.predicted_label,
            anomaly_score=anomaly_score,
            anomaly=anomaly, threat_label=label, threat_confidence=confidence,
            risk_score=round(risk_score, 6), processing_ms=round((perf_counter() - started) * 1000, 3),
        )
        return ProcessedLog(inference=result, routes=route_result(result))
