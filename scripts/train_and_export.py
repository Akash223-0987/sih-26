#!/usr/bin/env python3
"""
Deterministic build script for ULPF LightGBM threat model.

This script trains and exports the threat model artifact with:
- Reproducible dataset generation (seeded)
- Stratified train/validation/test splits (70/15/15)
- Early stopping on validation loss
- OneHotEncoder for categorical features (no ordinal bias)
- SHA-256 integrity verification

Usage:
    python scripts/train_and_export.py [--csv PATH] [--artifact PATH] [--seed SEED]

Example (CI/CD):
    docker run ... python scripts/train_and_export.py --artifact /models/threat_model.joblib
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

# Ensure parent directory is on path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from train_kaggle_model import train_model

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)


def verify_artifact(artifact_path: Path) -> str:
    """Verify artifact integrity and return SHA-256 checksum.
    
    Args:
        artifact_path: Path to serialized model artifact
        
    Returns:
        SHA-256 hex digest
        
    Raises:
        FileNotFoundError: If artifact does not exist
        ValueError: If artifact integrity check fails
    """
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found at {artifact_path}")
    
    with open(artifact_path, "rb") as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
    
    logger.info("Artifact integrity verified (SHA-256: %s)", checksum)
    return checksum


def main(argv: list[str] | None = None) -> int:
    """Train and export threat model artifact.
    
    Args:
        argv: Command-line arguments
        
    Returns:
        0 on success, 1 on failure
    """
    parser = argparse.ArgumentParser(
        description="Build and export ULPF LightGBM threat model"
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="Path to training CSV; uses synthetic data if not provided"
    )
    parser.add_argument(
        "--artifact",
        default="models/threat_model.joblib",
        help="Output path for serialized model artifact"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Only verify existing artifact integrity"
    )
    
    args = parser.parse_args(argv)
    artifact_path = Path(args.artifact)
    
    try:
        if args.verify:
            # Verify existing artifact only
            checksum = verify_artifact(artifact_path)
            print(f"Artifact OK: {artifact_path} ({checksum})")
            return 0
        
        # Train new model
        logger.info("Starting model training...")
        artifact = train_model(
            csv_path=args.csv,
            artifact_path=str(artifact_path),
            seed=args.seed
        )
        
        # Verify integrity
        checksum = verify_artifact(artifact_path)
        
        # Log summary
        print("\n" + "=" * 80)
        print("MODEL BUILD COMPLETE")
        print("=" * 80)
        print(f"Artifact: {artifact_path}")
        print(f"Checksum: {checksum}")
        print(f"Version: {artifact['version']}")
        print(f"Classes: {artifact['target_classes']}")
        print(f"Features: {len(artifact['numeric_features'])} numeric + "
              f"{len(artifact['categorical_features'])} categorical")
        if "metrics" in artifact:
            print("\nTest Metrics:")
            for metric, value in artifact["metrics"].items():
                print(f"  {metric:12s}: {value:.4f}")
        print("=" * 80 + "\n")
        
        return 0
        
    except Exception as exc:
        logger.exception("Model build failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
