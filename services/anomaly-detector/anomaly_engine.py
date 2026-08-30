from __future__ import annotations

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# Core telemetry metric bounds for baseline z-scoring
DEFAULT_BASELINES: Dict[str, Tuple[float, float]] = {
    "bytes_in": (1000.0, 500.0),       # (mean, std)
    "bytes_out": (500.0, 300.0),
    "auth_failures": (0.1, 0.5),
    "auth_successes": (1.0, 1.0),
    "in_degree": (3.0, 2.0),
    "avg_span_duration_ms": (20.0, 15.0),
    "max_call_depth": (2.0, 1.0),
    "error_flag": (0.05, 0.22),
}


class StatisticalAnomalyScorer:
    """Computes statistical z-scores and metric deviation indicators."""

    def __init__(self, baselines: Optional[Dict[str, Tuple[float, float]]] = None) -> None:
        self.baselines = baselines or DEFAULT_BASELINES

    def compute_z_scores(self, telemetry: Dict[str, Any]) -> Dict[str, float]:
        z_scores: Dict[str, float] = {}
        for metric, (mean, std) in self.baselines.items():
            val = float(telemetry.get(metric, 0.0) or 0.0)
            if std > 0:
                z_scores[metric] = round((val - mean) / std, 3)
            else:
                z_scores[metric] = 0.0
        return z_scores

    def evaluate(self, telemetry: Dict[str, Any]) -> Tuple[float, List[str]]:
        z_scores = self.compute_z_scores(telemetry)
        reasons: List[str] = []
        max_z = 0.0

        for metric, z in z_scores.items():
            if z >= 3.0:
                val = telemetry.get(metric, 0.0)
                reasons.append(f"Metric '{metric}' spiked to {val} (z-score: {z:.2f})")
                if z > max_z:
                    max_z = z

        # Normalize z-score into [0.0, 1.0] using sigmoid transform
        if max_z <= 0:
            score = 0.05
        else:
            score = float(1.0 / (1.0 + math.exp(-0.5 * (max_z - 3.0))))
            score = round(min(1.0, max(0.0, score)), 4)

        return score, reasons


class IsolationForestAnomalyDetector:
    """Unsupervised Outlier & Zero-Day Threat Detector using Isolation Forest."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
        )
        self.is_fitted = False
        self._fit_default_baseline()

    def _fit_default_baseline(self) -> None:
        """Fit Isolation Forest on synthetic normal operational traffic baseline."""
        rng = np.random.RandomState(self.random_state)
        normal_samples = 1000

        # Normal operational distribution
        bytes_in = rng.normal(1000, 200, normal_samples).clip(0)
        bytes_out = rng.normal(500, 100, normal_samples).clip(0)
        auth_fail = rng.poisson(0.1, normal_samples)
        auth_succ = rng.poisson(1.0, normal_samples)
        in_degree = rng.poisson(3, normal_samples)
        avg_span = rng.normal(20, 5, normal_samples).clip(1)
        call_depth = rng.poisson(2, normal_samples)
        error_flag = rng.binomial(1, 0.05, normal_samples)

        X_baseline = np.column_stack([
            bytes_in, bytes_out, auth_fail, auth_succ,
            in_degree, avg_span, call_depth, error_flag
        ])
        self.model.fit(X_baseline)
        self.is_fitted = True

    def extract_features(self, telemetry: Dict[str, Any]) -> np.ndarray:
        return np.array([[
            float(telemetry.get("bytes_in", 0.0) or 0.0),
            float(telemetry.get("bytes_out", 0.0) or 0.0),
            float(telemetry.get("auth_failures", 0.0) or 0.0),
            float(telemetry.get("auth_successes", 0.0) or 0.0),
            float(telemetry.get("in_degree", 0.0) or 0.0),
            float(telemetry.get("avg_span_duration_ms", 0.0) or 0.0),
            float(telemetry.get("max_call_depth", 0.0) or 0.0),
            float(telemetry.get("error_flag", 0.0) or 0.0),
        ]])

    def predict_anomaly_score(self, telemetry: Dict[str, Any]) -> float:
        if not self.is_fitted:
            return 0.1
        X = self.extract_features(telemetry)
        # decision_function outputs negative scores for outliers, positive for inliers
        raw_score = self.model.decision_function(X)[0]
        # Invert and scale to [0.0, 1.0]
        # Normal scores ~ 0.15+, outliers ~ -0.2 to -0.4
        anomaly_score = float(0.5 - raw_score)
        return float(round(min(1.0, max(0.0, anomaly_score)), 4))


class HybridAnomalyEngine:
    """Fuses statistical z-scores and unsupervised Isolation Forest for complete anomaly detection."""

    def __init__(self) -> None:
        self.stat_scorer = StatisticalAnomalyScorer()
        self.iso_forest = IsolationForestAnomalyDetector()

    def detect(self, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        stat_score, stat_reasons = self.stat_scorer.evaluate(telemetry)
        iso_score = self.iso_forest.predict_anomaly_score(telemetry)

        # Composite fused score (weighted max)
        fused_score = round(max(stat_score, iso_score * 0.9, (stat_score + iso_score) / 2.0), 4)
        is_anomaly = fused_score >= 0.65

        risk_level = "LOW"
        if fused_score >= 0.85:
            risk_level = "CRITICAL"
        elif fused_score >= 0.70:
            risk_level = "HIGH"
        elif fused_score >= 0.50:
            risk_level = "MEDIUM"

        return {
            "event_id": str(telemetry.get("event_id", "unknown")),
            "anomaly_score": fused_score,
            "statistical_score": stat_score,
            "isolation_forest_score": iso_score,
            "is_anomaly": is_anomaly,
            "risk_level": risk_level,
            "reasons": stat_reasons,
        }
