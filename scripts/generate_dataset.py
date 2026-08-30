#!/usr/bin/env python3
"""Generate seeded, noisy ULPF telemetry for local and air-gapped training."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

NUMERIC_FEATURES = [
    "bytes_in", "bytes_out", "src_port", "dst_port", "auth_failures",
    "auth_successes", "in_degree", "avg_span_duration_ms", "max_call_depth", "error_flag",
]
TARGET_COLUMN = "threat_label"
TARGET_CLASSES = ["Benign", "Brute Force", "Lateral Movement", "Exfiltration", "Port Scan"]


def generate_dataset(rows: int = 50000, seed: int = 42) -> pd.DataFrame:
    """Generate telemetry with overlap, malformed values, and OOD categories.

    Profiles describe broad behavior only. Multiplicative jitter, cross-class
    contamination, and invalid values prevent the label from being recovered
    by a deterministic threshold rule.
    """
    if rows < len(TARGET_CLASSES):
        raise ValueError("rows must provide at least one sample per class")
    rng = np.random.default_rng(seed)
    weights = np.array([0.70, 0.15, 0.08, 0.04, 0.03])
    labels = rng.choice(TARGET_CLASSES, size=rows, p=weights / weights.sum())
    profiles: dict[str, tuple[float, ...]] = {
        "Benign": (800, 700, 12000, 443, 2, 8, 2, 30, 2, 0.04),
        "Brute Force": (260, 180, 8000, 22, 18, 2, 3, 20, 2, 0.35),
        "Lateral Movement": (1100, 900, 10000, 445, 5, 7, 12, 45, 5, 0.25),
        "Exfiltration": (1800, 18000, 11000, 443, 3, 4, 5, 55, 4, 0.12),
        "Port Scan": (90, 70, 5000, 22, 1, 1, 35, 4, 1, 0.08),
    }
    protocols = ["tcp", "udp", "ssh", "https", "quic", "sctp", "unknown"]
    records: list[dict[str, Any]] = []
    for label in labels:
        means = np.asarray(profiles[str(label)], dtype=float)
        scale = rng.lognormal(mean=0.0, sigma=0.30, size=10)
        values = means * scale * np.exp(rng.normal(0.0, 0.22, size=10))
        values = np.maximum(values, 0.0)

        # 7% ambiguous samples borrow the neighboring class's broad profile.
        if rng.random() < 0.12:
            other = str(rng.choice([item for item in TARGET_CLASSES if item != label]))
            other_means = np.asarray(profiles[other], dtype=float)
            blend = rng.uniform(0.35, 0.65)
            values = blend * values + (1.0 - blend) * other_means
        record = dict(zip(NUMERIC_FEATURES, values.tolist()))
        record["protocol"] = str(rng.choice(protocols[:5] if rng.random() > 0.04 else protocols[5:]))
        record[TARGET_COLUMN] = str(label)
        records.append(record)

    frame = pd.DataFrame(records)
    # Irreducible annotation ambiguity: a small fraction of events carry a
    # plausible neighboring label even though their telemetry is unchanged.
    overlap_count = max(1, int(rows * 0.06))
    overlap_indices = rng.choice(frame.index, size=overlap_count, replace=False)
    for index in overlap_indices:
        current = frame.at[index, TARGET_COLUMN]
        alternatives = [item for item in TARGET_CLASSES if item != current]
        frame.at[index, TARGET_COLUMN] = str(rng.choice(alternatives))
    # OOD and malformed values are intentionally sparse and are handled by the
    # trainer's numeric coercion and unknown-category paths.
    ood_count = max(1, int(rows * 0.02))
    frame[NUMERIC_FEATURES] = frame[NUMERIC_FEATURES].astype(object)
    ood_indices = rng.choice(frame.index, size=ood_count, replace=False)
    frame.loc[ood_indices[:ood_count // 2], "protocol"] = rng.choice(
        ["gre", "wireguard", "vendor-proto-99"], size=max(1, ood_count // 2)
    )
    malformed_indices = ood_indices[ood_count // 2:]
    for index in malformed_indices:
        column = str(rng.choice(NUMERIC_FEATURES))
        frame.loc[index, column] = rng.choice(["n/a", "-", "overflow", "nan"])
    return frame


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate noisy ULPF training telemetry")
    parser.add_argument("--output", default="data/ulpf_training.csv")
    parser.add_argument("--rows", type=int, default=50000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    generate_dataset(args.rows, args.seed).to_csv(output, index=False)
    print(f"Generated {args.rows} rows at {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
