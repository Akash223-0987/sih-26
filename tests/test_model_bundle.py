from __future__ import annotations

import hashlib
import pickle
from pathlib import Path

import pytest

from pytrace.ml.model_bundle import export_model_bundle, load_model_bundle


def test_pickle_bundle_exports_hash_and_loads(tmp_path: Path) -> None:
    output = tmp_path / "threat_model.pkl"
    checksum = export_model_bundle("models/threat_model.joblib", str(output))

    assert output.is_file()
    assert Path(f"{output}.sha256").read_text(encoding="ascii").startswith(checksum)
    assert checksum == hashlib.sha256(output.read_bytes()).hexdigest()

    bundle = load_model_bundle(str(output), expected_sha256=checksum)
    assert set(bundle) == {"model", "classes", "protocol_lookup", "feature_names", "version", "metrics"}
    assert bundle["protocol_lookup"]["unknown"] == [0.0] * len(bundle["protocol_lookup"]["unknown"])


def test_pickle_bundle_rejects_wrong_hash(tmp_path: Path) -> None:
    output = tmp_path / "threat_model.pkl"
    export_model_bundle("models/threat_model.joblib", str(output))

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_model_bundle(str(output), expected_sha256="0" * 64)


def test_pickle_bundle_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_model_bundle(str(tmp_path / "missing.pkl"))