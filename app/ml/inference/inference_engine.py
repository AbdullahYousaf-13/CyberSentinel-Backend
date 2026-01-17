import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np

logger = logging.getLogger(__name__)


class InferenceEngine:
    def __init__(self, model_dir: str, integrity_required: bool) -> None:
        self._model_dir = Path(model_dir)
        self._integrity_required = integrity_required
        self._iforest = None
        self._rf = None
        self._metadata: Dict[str, Any] = {}

    def load_version(self, version: str) -> None:
        version_path = self._model_dir / "versions" / version
        metadata_path = version_path / "metadata.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"Missing metadata for model version {version}")

        self._metadata = json.loads(metadata_path.read_text(encoding="ascii"))
        iforest_path = version_path / "isolation_forest.joblib"
        rf_path = version_path / "random_forest.joblib"

        if self._integrity_required:
            self._verify_hash(iforest_path, self._metadata["hashes"]["isolation_forest"])
            self._verify_hash(rf_path, self._metadata["hashes"]["random_forest"])

        self._iforest = joblib.load(iforest_path)
        self._rf = joblib.load(rf_path)
        logger.info("Loaded ML models for version %s", version)

    def predict(self, features: np.ndarray, threshold: float) -> Dict[str, Any]:
        if self._iforest is None or self._rf is None:
            raise RuntimeError("Models not loaded")

        anomaly_scores = -self._iforest.score_samples(features)
        rf_probs = self._rf.predict_proba(features)
        rf_preds = self._rf.predict(features)

        results = []
        for idx, score in enumerate(anomaly_scores):
            rf_prob = float(max(rf_probs[idx]))
            classification = str(rf_preds[idx]) if rf_prob >= 0.7 else None
            # Favor known-attack classification when confidence is high to reduce false positives.
            if classification:
                results.append({"alert_type": "known_attack", "classification": classification, "score": score})
            elif score >= threshold:
                results.append({"alert_type": "anomaly", "classification": None, "score": score})
            else:
                results.append({"alert_type": "benign", "classification": None, "score": score})
        return {"results": results}

    @staticmethod
    def _verify_hash(path: Path, expected_hash: str) -> None:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_hash:
            raise ValueError(f"Model integrity check failed for {path.name}")
