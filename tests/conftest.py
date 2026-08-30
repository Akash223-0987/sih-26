from __future__ import annotations

import sys
from pathlib import Path

# Add ML-Analyzer microservice directory to sys.path for test resolution
_ml_analyzer_dir = str(Path(__file__).parent.parent / "services" / "ML-Analyzer")
if _ml_analyzer_dir not in sys.path:
    sys.path.insert(0, _ml_analyzer_dir)
