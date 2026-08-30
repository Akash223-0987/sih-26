import hashlib
import math
import re
from typing import List

_TOKEN = re.compile(r"[a-zA-Z0-9_.:-]+")


class LogVectorizer:
    """Dependency-free hashing vectorizer; replaceable with ONNX/FastEmbed adapter."""

    def __init__(self, dimensions: int = 32):
        if dimensions < 4:
            raise ValueError("dimensions must be at least 4")
        self.dimensions = dimensions

    def transform(self, text: str) -> List[float]:
        vector = [0.0] * self.dimensions
        tokens = _TOKEN.findall(text.lower()) or ["empty"]
        for token in tokens:
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimensions
            vector[index] += 1.0 if digest[4] & 1 else -1.0
        norm = math.sqrt(sum(value * value for value in vector)) or 1.0
        return [round(value / norm, 6) for value in vector]
