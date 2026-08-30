"""Atomic pickle export and verification for ULPF threat model bundles."""

from __future__ import annotations

import hashlib
import os
import pickle
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import numpy as np

REQUIRED_KEYS = frozenset({
    "model", "classes", "protocol_lookup", "feature_names", "version", "metrics",
})


def _artifact_path(output_path: str | Path) -> Path:
    path = Path(output_path)
    return path if path.suffix == ".pkl" else Path(f"{path}.pkl")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_bytes(path: Path, writer: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False
        ) as stream:
            temporary_path = Path(stream.name)
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def _protocol_lookup(artifact: Dict[str, Any]) -> Dict[str, list[float]]:
    encoder = artifact.get("protocol_encoder")
    categories = getattr(encoder, "categories_", None)
    if not categories or len(categories) != 1:
        raise ValueError("artifact protocol_encoder is not fitted")
    values = [str(value).casefold() for value in categories[0]]
    width = len(values)
    lookup = {value: np.eye(width, dtype=float)[index].tolist() for index, value in enumerate(values)}
    lookup["unknown"] = [0.0] * width
    return lookup


def _bundle_from_artifact(artifact: Dict[str, Any]) -> Dict[str, Any]:
    if "model" not in artifact:
        raise ValueError("source artifact is missing model")
    label_encoder = artifact.get("label_encoder")
    classes: Sequence[Any] = getattr(label_encoder, "classes_", artifact.get("target_classes", []))
    feature_names = artifact.get("feature_columns") or artifact.get("feature_names")
    if len(classes) == 0 or len(feature_names) == 0:
        raise ValueError("source artifact is missing classes or feature names")
    return {
        "model": artifact["model"],
        "classes": [str(value) for value in classes],
        "protocol_lookup": _protocol_lookup(artifact),
        "feature_names": [str(value) for value in feature_names],
        "version": str(artifact.get("version", "unknown")),
        "metrics": dict(artifact.get("metrics", {})),
    }


def export_model_bundle(
    source_artifact_path: str = "models/threat_model.joblib",
    output_path: str = "models/threat_model.pkl",
) -> str:
    """Export a trained joblib artifact to an atomic, hashed pickle bundle."""
    source = Path(source_artifact_path)
    if not source.is_file():
        raise FileNotFoundError(f"source model artifact does not exist: {source}")
    with source.open("rb") as stream:
        import joblib
        artifact = joblib.load(stream)
    if not isinstance(artifact, dict):
        raise ValueError("source model artifact must contain a dictionary")
    bundle = _bundle_from_artifact(artifact)
    destination = _artifact_path(output_path)
    _atomic_bytes(destination, lambda stream: pickle.dump(bundle, stream, protocol=pickle.HIGHEST_PROTOCOL))
    checksum = _sha256(destination)
    sidecar = Path(f"{destination}.sha256")
    _atomic_bytes(sidecar, lambda stream: stream.write(f"{checksum}  {destination.name}\n".encode("ascii")))
    print(f"SHA-256 ({destination}): {checksum}")
    return checksum


def _validate_bundle(bundle: Any) -> Dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValueError("pickle payload must be a dictionary")
    missing = REQUIRED_KEYS.difference(bundle)
    if missing:
        raise ValueError(f"pickle bundle is missing keys: {sorted(missing)}")
    if not isinstance(bundle["classes"], list) or not bundle["classes"]:
        raise ValueError("bundle classes must be a non-empty list")
    if not isinstance(bundle["feature_names"], list) or not bundle["feature_names"]:
        raise ValueError("bundle feature_names must be a non-empty list")
    if not isinstance(bundle["protocol_lookup"], dict) or "unknown" not in bundle["protocol_lookup"]:
        raise ValueError("bundle protocol_lookup must include unknown")
    return bundle


def load_model_bundle(pkl_path: str, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Verify, load, and smoke-test a serialized ULPF pickle bundle."""
    path = Path(pkl_path)
    if not path.is_file():
        raise FileNotFoundError(f"pickle model bundle does not exist: {path}")
    checksum = _sha256(path)
    if expected_sha256 is not None and checksum.casefold() != expected_sha256.strip().casefold():
        raise ValueError(f"SHA-256 mismatch for {path}: expected {expected_sha256}, got {checksum}")
    try:
        with path.open("rb") as stream:
            bundle = _validate_bundle(pickle.load(stream))
    except (OSError, pickle.PickleError, EOFError, ValueError, TypeError) as exc:
        raise ValueError(f"failed to load model bundle {path}: {exc}") from exc
    try:
        model_width = getattr(bundle["model"], "n_features_in_", None)
        numeric_width = len(bundle["feature_names"]) - 1
        categorical_width = len(bundle["protocol_lookup"]["unknown"])
        width = int(model_width or numeric_width + categorical_width)
        vector = np.zeros((1, width), dtype=np.float32)
        probabilities = np.asarray(bundle["model"].predict_proba(vector))
        if probabilities.ndim != 2 or probabilities.shape[0] != 1:
            raise ValueError("model predict_proba returned an invalid shape")
    except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
        raise ValueError(f"model bundle failed dummy inference: {exc}") from exc
    return bundle