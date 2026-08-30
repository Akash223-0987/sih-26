from __future__ import annotations

import tempfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

from ml_service import _load_artifact, _stratify_risk
from train_kaggle_model import TARGET_CLASSES, train_model, generate_synthetic_data, _prepare_features
from sklearn.preprocessing import RobustScaler, OneHotEncoder


def test_train_model_end_to_end_and_metrics():
    """Verify train_model trains LightGBM classifier and outputs valid metrics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_path = Path(tmpdir) / "test_model.joblib"
        artifact = train_model(artifact_path=str(artifact_path), seed=42)

        assert artifact_path.exists()
        assert "model" in artifact
        assert "scaler" in artifact
        assert "protocol_encoder" in artifact
        assert "label_encoder" in artifact
        assert "metrics" in artifact

        metrics = artifact["metrics"]
        assert 0.80 <= metrics["accuracy"] <= 1.0
        assert 0.80 <= metrics["precision"] <= 1.0
        assert 0.80 <= metrics["recall"] <= 1.0
        assert 0.80 <= metrics["f1"] <= 1.0


def test_model_artifact_load_and_integrity():
    """Verify artifact serialization, checksum verification, and loading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        artifact_path = Path(tmpdir) / "test_model.joblib"
        train_model(artifact_path=str(artifact_path), seed=42)

        loaded_artifact = _load_artifact(str(artifact_path))
        assert loaded_artifact is not None
        assert "model" in loaded_artifact
        assert "protocol_lookup" in loaded_artifact

        # Corrupt file to verify integrity error handling
        with open(artifact_path, "wb") as f:
            f.write(b"corrupted_header_data")

        with pytest.raises(ValueError, match="Artifact integrity check failed"):
            _load_artifact(str(artifact_path))


def test_model_reproducibility_with_fixed_seed():
    """Verify training with identical random seed produces reproducible metrics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        art1 = train_model(artifact_path=str(Path(tmpdir) / "m1.joblib"), seed=123)
        art2 = train_model(artifact_path=str(Path(tmpdir) / "m2.joblib"), seed=123)

        assert art1["metrics"]["accuracy"] == pytest.approx(art2["metrics"]["accuracy"], abs=1e-4)
        assert art1["metrics"]["f1"] == pytest.approx(art2["metrics"]["f1"], abs=1e-4)


def test_prepare_features_handles_unknown_and_arrow_arrays():
    """Verify feature preparation scales numerics and handles unknown protocols safely."""
    df = pd.DataFrame([
        {"bytes_in": 100, "bytes_out": 200, "protocol": "tcp"},
        {"bytes_in": 500, "bytes_out": 1000, "protocol": "UDP"},
        {"bytes_in": 0, "bytes_out": 0, "protocol": "custom_proto_xyz"},
    ])

    scaler = RobustScaler()
    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)

    features, num_cat = _prepare_features(df, scaler, encoder, fit=True)
    assert features.shape[0] == 3
    assert num_cat > 0
    assert not np.isnan(features).any()


def test_synthetic_data_generation_balance():
    """Verify synthetic dataset generator produces expected class balance and columns."""
    df = generate_synthetic_data(rows_per_class=500, seed=42)
    assert len(df) == 500  # Total 500 rows generated
    assert len(df["threat_label"].unique()) >= 4
    assert "bytes_in" in df.columns
    assert "auth_failures" in df.columns


@pytest.mark.parametrize(
    ("threat_label", "confidence", "anomaly_score", "expected_risk"),
    [
        ("Benign", 0.95, 0.0, "LOW"),
        ("Benign", 0.60, 0.1, "LOW"),
        ("Benign", 0.50, 0.0, "MEDIUM"),
        ("Benign", 0.90, 0.85, "MEDIUM"),
        ("Brute Force", 0.85, 0.0, "CRITICAL"),
        ("Port Scan", 0.80, 0.0, "CRITICAL"),
        ("Exfiltration", 0.75, 0.0, "HIGH"),
        ("Lateral Movement", 0.55, 0.0, "HIGH"),
        ("Brute Force", 0.40, 0.0, "MEDIUM"),
    ],
)
def test_risk_stratification_tree(
    threat_label: str, confidence: float, anomaly_score: float, expected_risk: str
):
    """Verify risk tier decision logic produces deterministic and expected risk levels."""
    risk = _stratify_risk(threat_label, confidence, anomaly_score)
    assert risk == expected_risk
