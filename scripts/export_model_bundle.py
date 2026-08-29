#!/usr/bin/env python3
"""Export and verify the ULPF LightGBM pickle bundle."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pytrace.ml.model_bundle import export_model_bundle, load_model_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a ULPF model as an atomic pickle bundle")
    parser.add_argument("--source", default="models/threat_model.joblib")
    parser.add_argument("--output", default="models/threat_model.pkl")
    args = parser.parse_args(argv)
    checksum = export_model_bundle(args.source, args.output)
    load_model_bundle(str(Path(args.output).with_suffix(".pkl")), expected_sha256=checksum)
    print("Model bundle verification: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())