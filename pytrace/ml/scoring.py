from collections import deque
from typing import Deque, List, Tuple


class OnlineAnomalyDetector:
    """Small online distance detector with stable cold-start behavior."""

    def __init__(self, window_size: int = 256, threshold: float = 0.72):
        self.samples: Deque[List[float]] = deque(maxlen=window_size)
        self.threshold = threshold

    def score(self, vector: List[float]) -> Tuple[float, bool]:
        if len(self.samples) < 4:
            score = 0.0
        else:
            mean = [sum(sample[i] for sample in self.samples) / len(self.samples) for i in range(len(vector))]
            distance = sum((value - mean[i]) ** 2 for i, value in enumerate(vector)) / len(vector)
            score = min(1.0, distance ** 0.5)
        self.samples.append(vector)
        return round(score, 6), score >= self.threshold


class ThreatClassifier:
    LABELS = ("Benign", "Port Scan", "Brute Force", "Exfiltration", "Lateral Movement")

    def classify(self, text: str, anomaly_score: float) -> Tuple[str, float]:
        lowered = text.lower()
        rules = (
            ("Port Scan", ("port scan", "port_scan", "nmap", "syn scan", "masscan")),
            ("Brute Force", ("brute force", "failed password", "authentication failure", "invalid user")),
            ("Exfiltration", ("exfil", "data transfer", "large upload", "staged data")),
            ("Lateral Movement", ("lateral", "psexec", "pass-the-hash", "remote service")),
        )
        for label, indicators in rules:
            if any(indicator in lowered for indicator in indicators):
                return label, round(min(1.0, 0.72 + anomaly_score * 0.28), 6)
        return "Benign", round(max(0.5, 1.0 - anomaly_score), 6)
