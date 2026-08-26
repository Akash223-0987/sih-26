"""Offline-capable, multi-stage log inference engine.

The ONNX path is deliberately local-only. If the model directory is absent,
or optional ONNX dependencies are unavailable, the deterministic fallback is
used without attempting a network request.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from pytrace.ml.features import LogVectorizer

THREAT_LABELS: Tuple[str, ...] = (
    "Benign",
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Exfiltration",
    "Lateral Movement",
)

_EPHEMERAL_TOKEN = re.compile(
    r"\b(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?|"
    r"[0-9a-f]{16,}|[A-Za-z0-9_-]{24,})\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ModelOutput:
    embedding: List[float]
    predicted_label: str
    threat_confidence: float
    anomaly_score: float
    preprocessed_text: str
    raw_log_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "embedding": self.embedding,
            "predicted_label": self.predicted_label,
            "threat_confidence": self.threat_confidence,
            "anomaly_score": self.anomaly_score,
            "raw_log_sha256": self.raw_log_sha256,
        }


class LocalOnnxEncoder:
    """Load a local ONNX encoder only when all required local assets exist."""

    def __init__(self, model_dir: Optional[str], dimensions: int):
        self.dimensions = dimensions
        self.session = None
        self.tokenizer = None
        if not model_dir:
            return
        model_path = Path(model_dir) / "model.onnx"
        if not model_path.is_file():
            return
        try:
            import onnxruntime  # type: ignore[import-not-found]
            from transformers import AutoTokenizer  # type: ignore[import-not-found]

            self.session = onnxruntime.InferenceSession(
                str(model_path), providers=["CPUExecutionProvider"]
            )
            self.tokenizer = AutoTokenizer.from_pretrained(
                str(model_dir), local_files_only=True
            )
        except (ImportError, OSError, RuntimeError, ValueError):
            self.session = None
            self.tokenizer = None

    @property
    def available(self) -> bool:
        return self.session is not None

    def encode(self, text: str) -> Optional[List[float]]:
        """Return an ONNX embedding when a compatible local adapter is supplied.

        Tokenization/model-specific input names vary between exported MiniLM
        artifacts. The generic engine therefore keeps this adapter conservative
        and falls back rather than guessing an incompatible tensor contract.
        """
        if self.session is None or self.tokenizer is None:
            return None
        try:
            import numpy as np

            encoded = self.tokenizer(
                text, return_tensors="np", truncation=True, max_length=256
            )
            inputs = {
                item.name: encoded[item.name]
                for item in self.session.get_inputs()
                if item.name in encoded
            }
            outputs = self.session.run(None, inputs)
            values = np.asarray(outputs[0], dtype=np.float32)
            if values.ndim == 3:
                mask = encoded.get("attention_mask", np.ones(values.shape[1]))
                values = (values * mask[..., None]).sum(axis=1) / max(1, mask.sum())
            flattened = values.reshape(-1).tolist()
            return [float(value) for value in flattened] if len(flattened) == self.dimensions else None
        except (KeyError, OSError, RuntimeError, ValueError, TypeError):
            return None


class CalibratedLinearClassifier:
    """Small deterministic linear head with temperature-scaled softmax."""

    _INDICATORS = {
        "Reconnaissance": ("nmap", "masscan", "port scan", "port_scan", "scan"),
        "Initial Access": ("phishing", "exploit", "payload", "initial access"),
        "Execution": ("powershell", "cmd.exe", "script", "execute"),
        "Exfiltration": ("exfil", "large upload", "staged data", "data transfer", "dns tunneling", "curl payload"),
        "Lateral Movement": ("lateral", "pass-the-hash", "remote service", "winrm"),
        "Brute Force": ("failed password", "invalid user", "brute force", "authentication failure"),
    }

    def __init__(self, temperature: float = 1.0):
        if temperature <= 0:
            raise ValueError("temperature must be positive")
        self.temperature = temperature

    def predict(self, text: str, embedding: Sequence[float]) -> Tuple[str, float]:
        lowered = text.casefold()
        logits = [0.0] * len(THREAT_LABELS)
        for index, label in enumerate(THREAT_LABELS[1:], start=1):
            logits[index] = sum(
                2.5 for indicator in self._INDICATORS[label] if indicator in lowered
            )
        if any(indicator in lowered for indicator in self._INDICATORS["Brute Force"]):
            logits[2] = 2.5
        # A weak deterministic feature prevents every unknown vector having
        # identical logits while leaving lexical evidence dominant.
        logits[0] = 0.25 + 0.05 * sum(abs(value) for value in embedding)
        scaled = [value / self.temperature for value in logits]
        maximum = max(scaled)
        exponentials = [math.exp(value - maximum) for value in scaled]
        total = sum(exponentials) or 1.0
        probabilities = [value / total for value in exponentials]
        best = max(range(len(probabilities)), key=probabilities.__getitem__)
        return THREAT_LABELS[best], round(probabilities[best], 6)


class DecayedAnomalyScorer:
    """Streaming distance scorer with exponential baseline updates."""

    def __init__(self, dimensions: int, threshold: float = 0.72, decay: float = 0.05):
        if not 0.0 < decay <= 1.0:
            raise ValueError("decay must be in the interval (0, 1]")
        self.threshold = threshold
        self.decay = decay
        self.mean = [0.0] * dimensions
        self.count = 0

    def score(self, vector: Sequence[float]) -> Tuple[float, bool]:
        if self.count == 0:
            distance = 0.0
        else:
            distance = math.sqrt(
                sum((value - self.mean[index]) ** 2 for index, value in enumerate(vector))
                / max(1, len(vector))
            )
        weight = self.decay if self.count else 1.0
        for index, value in enumerate(vector):
            self.mean[index] = (1.0 - weight) * self.mean[index] + weight * value
        self.count += 1
        bounded = round(min(1.0, max(0.0, distance)), 6)
        return bounded, bounded >= self.threshold

    def warmup(self, vectors: Iterable[Sequence[float]]) -> None:
        for vector in vectors:
            for index, value in enumerate(vector):
                self.mean[index] = value
            self.count += 1


class ModelEngine:
    """Three-stage representation, classification, and anomaly engine."""

    def __init__(
        self,
        dimensions: int = 384,
        model_dir: Optional[str] = None,
        anomaly_threshold: float = 0.72,
        anomaly_decay: float = 0.05,
        temperature: float = 1.0,
    ):
        if dimensions < 4:
            raise ValueError("dimensions must be at least 4")
        self.dimensions = dimensions
        self.fallback = LogVectorizer(dimensions)
        self.onnx = LocalOnnxEncoder(model_dir, dimensions)
        self.classifier = CalibratedLinearClassifier(temperature)
        self.anomaly = DecayedAnomalyScorer(dimensions, anomaly_threshold, anomaly_decay)

    @staticmethod
    def preprocess(text: str) -> str:
        return _EPHEMERAL_TOKEN.sub("<EPHEMERAL>", text or "")

    def warmup(self, sample_logs: Optional[List[str]] = None) -> None:
        """Warm local resources without downloading models or contacting hosts."""
        samples = sample_logs or [""]
        vectors = []
        for sample in samples:
            text = self.preprocess(sample)
            vectors.append(self.onnx.encode(text) or self.fallback.transform(text))
        self.anomaly.warmup(vectors)

    def infer(self, raw_text: str) -> ModelOutput:
        text = self.preprocess(raw_text)
        embedding = self.onnx.encode(text) if self.onnx.available else None
        embedding = embedding or self.fallback.transform(text)
        anomaly_score, _ = self.anomaly.score(embedding)
        label, confidence = self.classifier.predict(text, embedding)
        return ModelOutput(
            embedding, label, confidence, anomaly_score, text,
            hashlib.sha256(raw_text.encode("utf-8")).hexdigest(),
        )
