import logging
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)


class FeatureExtractor:
    def __init__(self) -> None:
        self._severity_map = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}

    def transform(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        features = []
        for log in logs:
            message = str(log.get("message", ""))
            metadata = log.get("metadata", {}) or {}
            severity = str(log.get("severity", ""))
            timestamp = log.get("timestamp")
            hour = getattr(timestamp, "hour", 0)
            source = str(log.get("source", ""))
            source_hash = (sum(ord(ch) for ch in source) % 100) / 100.0

            feature_vector = [
                len(message) / 1000.0,
                len(metadata),
                self._severity_map.get(severity.lower(), 0.0),
                hour / 23.0,
                source_hash,
            ]
            features.append(feature_vector)
        return np.array(features, dtype=float)
