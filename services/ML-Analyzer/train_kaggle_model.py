from __future__ import annotations

import argparse
import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.preprocessing import OneHotEncoder, RobustScaler, LabelEncoder
from lightgbm import early_stopping, log_evaluation

logger = logging.getLogger(__name__)
TARGET_CLASSES = ["Benign", "Brute Force", "Lateral Movement", "Exfiltration", "Port Scan"]
NUMERIC_FEATURES = [
    "bytes_in", "bytes_out", "src_port", "dst_port", "auth_failures",
    "auth_successes", "in_degree", "avg_span_duration_ms", "max_call_depth", "error_flag",
]
CATEGORICAL_FEATURES = ["protocol"]
FEATURE_COLUMNS = NUMERIC_FEATURES + CATEGORICAL_FEATURES
TARGET_COLUMN = "threat_label"
MIN_DATASET_SIZE = 50000


def generate_synthetic_data(rows_per_class: int = 10000, seed: int = 42) -> pd.DataFrame:
    """Compatibility wrapper around the standalone seeded dataset generator."""
    from scripts.generate_dataset import generate_dataset
    return generate_dataset(rows=max(1, rows_per_class), seed=seed)


def _prepare_features(
    frame: pd.DataFrame,
    scaler: RobustScaler,
    protocol_encoder: OneHotEncoder,
    fit: bool
) -> Tuple[np.ndarray, int]:
    """Prepare features: scale numerics, one-hot encode categoricals (no ordinal bias).
    
    Returns:
        (feature_matrix, num_categorical_features)
    """
    numeric = frame.reindex(columns=NUMERIC_FEATURES, fill_value=0).apply(pd.to_numeric, errors="coerce").fillna(0)
    categorical = frame.get("protocol", pd.Series("unknown", index=frame.index)).fillna("unknown").astype(str).str.lower()
    
    if fit:
        scaled = scaler.fit_transform(numeric.to_numpy())
        # Fit on all known protocols + unknown category
        protocol_encoder.fit(np.asarray(categorical).reshape(-1, 1))
    else:
        scaled = scaler.transform(numeric.to_numpy())
    
    # One-hot encode with handle_unknown='ignore' (unknown -> all zeros)
    # Convert sparse matrix to dense array if needed
    encoded_sparse = protocol_encoder.transform(np.asarray(categorical).reshape(-1, 1))
    encoded = encoded_sparse.toarray() if hasattr(encoded_sparse, 'toarray') else encoded_sparse
    feature_matrix = np.column_stack([scaled, encoded])
    num_cat_features = encoded.shape[1]
    
    return feature_matrix, num_cat_features


def train_model(
    csv_path: Optional[str] = None,
    artifact_path: str = "models/threat_model.joblib",
    seed: int = 42
) -> Dict[str, Any]:
    """Train and serialize LightGBM classifier with stratified validation split and early stopping."""
    # Load or generate dataset
    if csv_path and Path(csv_path).exists():
        frame = pd.read_csv(csv_path)
        logger.info("Training from %s with %d rows", csv_path, len(frame))
    else:
        frame = generate_synthetic_data(seed=seed)
        logger.info("Generated synthetic dataset with %d rows", len(frame))
    
    # Ensure minimum dataset size
    if len(frame) < MIN_DATASET_SIZE:
        logger.warning(
            "Dataset has %d rows (minimum: %d); expanding with additional synthetic samples",
            len(frame), MIN_DATASET_SIZE
        )
        synthetic_expansion = generate_synthetic_data(rows_per_class=MIN_DATASET_SIZE - len(frame), seed=seed + 1)
        frame = pd.concat([frame, synthetic_expansion], ignore_index=True)
    
    # Normalize target column
    target = next((name for name in (TARGET_COLUMN, "label", "Label", "attack_cat") if name in frame), None)
    if target is None:
        raise ValueError("Dataset must contain threat_label, label, Label, or attack_cat")
    frame = frame.rename(columns={target: TARGET_COLUMN})
    frame[TARGET_COLUMN] = frame[TARGET_COLUMN].map(lambda value: str(value).strip())
    frame = frame[frame[TARGET_COLUMN].isin(TARGET_CLASSES)].copy()
    if frame.empty:
        raise ValueError("Dataset contains none of the supported target classes")
    
    logger.info("Class distribution: %s", frame[TARGET_COLUMN].value_counts().to_dict())
    
    # Stratified train/validation/test split: 70/15/15
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=seed)
    train_idx, temp_idx = next(splitter.split(frame, frame[TARGET_COLUMN]))
    frame_train, frame_temp = frame.iloc[train_idx], frame.iloc[temp_idx]
    
    # Split temp (30%) into validation (15%) and test (15%)
    splitter_val = StratifiedShuffleSplit(n_splits=1, test_size=0.5, random_state=seed + 1)
    val_idx, test_idx = next(splitter_val.split(frame_temp, frame_temp[TARGET_COLUMN]))
    frame_val, frame_test = frame_temp.iloc[val_idx], frame_temp.iloc[test_idx]
    
    logger.info(
        "Split: train=%d, val=%d, test=%d",
        len(frame_train), len(frame_val), len(frame_test)
    )
    
    # Feature preparation with OneHotEncoder
    scaler = RobustScaler()
    protocol_encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    
    X_train, num_cat_features = _prepare_features(frame_train, scaler, protocol_encoder, fit=True)
    X_val, _ = _prepare_features(frame_val, scaler, protocol_encoder, fit=False)
    X_test, _ = _prepare_features(frame_test, scaler, protocol_encoder, fit=False)
    
    y_train = frame_train[TARGET_COLUMN].values
    y_val = frame_val[TARGET_COLUMN].values
    y_test = frame_test[TARGET_COLUMN].values
    
    # Encode labels
    label_encoder = LabelEncoder()
    label_encoder.fit(TARGET_CLASSES)
    y_train_encoded = label_encoder.transform(y_train)
    y_val_encoded = label_encoder.transform(y_val)
    y_test_encoded = label_encoder.transform(y_test)
    
    # Train LightGBM with early stopping
    model = LGBMClassifier(
        objective="multiclass",
        num_class=len(TARGET_CLASSES),
        class_weight="balanced",
        n_estimators=200,
        learning_rate=0.08,
        num_leaves=20,
        random_state=seed,
        verbosity=-1,
        n_jobs=1,
    )
    
    model.fit(
        X_train,
        y_train_encoded,
        eval_set=[(X_val, y_val_encoded)],
        eval_metric="multi_logloss",
        callbacks=[early_stopping(15), log_evaluation(period=0)],
    )
    
    # Evaluate on test set
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    y_pred_test = model.predict(X_test)
    accuracy = accuracy_score(y_test_encoded, y_pred_test)
    precision = precision_score(y_test_encoded, y_pred_test, average="weighted", zero_division=0)
    recall = recall_score(y_test_encoded, y_pred_test, average="weighted", zero_division=0)
    f1 = f1_score(y_test_encoded, y_pred_test, average="weighted", zero_division=0)
    
    logger.info(
        "Test metrics: accuracy=%.4f precision=%.4f recall=%.4f f1=%.4f",
        accuracy, precision, recall, f1
    )
    
    # Serialize artifact with integrity metadata
    artifact = {
        "model": model,
        "scaler": scaler,
        "protocol_encoder": protocol_encoder,
        "label_encoder": label_encoder,
        "feature_columns": FEATURE_COLUMNS,
        "numeric_features": NUMERIC_FEATURES,
        "categorical_features": CATEGORICAL_FEATURES,
        "num_categorical_features": num_cat_features,
        "target_classes": TARGET_CLASSES,
        "version": 2,
        "metrics": {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
        },
    }
    
    destination = Path(artifact_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, destination)
    
    # Compute and log SHA-256 checksum for integrity verification
    with open(destination, "rb") as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    logger.info("Model artifact saved to %s (SHA-256: %s)", destination, checksum)
    
    return artifact


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Train the ULPF LightGBM threat model")
    parser.add_argument("--csv", default=None)
    parser.add_argument("--artifact", default="models/threat_model.joblib")
    args = parser.parse_args(argv)
    train_model(args.csv, args.artifact)


if __name__ == "__main__":
    main()
