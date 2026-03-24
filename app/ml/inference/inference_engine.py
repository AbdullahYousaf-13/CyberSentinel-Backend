import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import sklearn

logger = logging.getLogger(__name__)


class InferenceEngine:
    def __init__(self, model_dir: str, integrity_required: bool) -> None:
        self._model_dir = Path(model_dir)
        self._integrity_required = integrity_required
        self._iforest = None
        self._rf = None
        self._expected_feature_count = None
        self._metadata: Dict[str, Any] = {}

    def load_version(self, version: str) -> None:
        version_path = self._model_dir / "versions" / version
        metadata_path = version_path / "metadata.json"
        if not metadata_path.exists():
            raise FileNotFoundError(f"Missing metadata for model version {version}")

        self._metadata = json.loads(metadata_path.read_text(encoding="ascii"))
        self._warn_if_runtime_version_mismatch(version)
        iforest_path = version_path / "isolation_forest.joblib"
        rf_path = version_path / "random_forest.joblib"

        if self._integrity_required:
            self._verify_hash(iforest_path, self._metadata["hashes"]["isolation_forest"])
            self._verify_hash(rf_path, self._metadata["hashes"]["random_forest"])

        self._iforest = joblib.load(iforest_path)
        self._rf = joblib.load(rf_path)
        self._validate_model_feature_compatibility()
        logger.info("Loaded ML models for version %s", version)

    def _warn_if_runtime_version_mismatch(self, version: str) -> None:
        trained_versions = self._metadata.get("library_versions") or {}
        trained_sklearn = trained_versions.get("scikit_learn")
        if trained_sklearn and trained_sklearn != sklearn.__version__:
            logger.warning(
                "Model version %s was recorded with scikit-learn %s but runtime uses %s",
                version,
                trained_sklearn,
                sklearn.__version__,
            )

    def predict(self, features: np.ndarray, threshold: float) -> Dict[str, Any]:
        if self._iforest is None or self._rf is None:
            raise RuntimeError("Models not loaded")
        self._validate_input_shape(features)

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

    def _validate_model_feature_compatibility(self) -> None:
        if not hasattr(self._iforest, "n_features_in_") or not hasattr(self._rf, "n_features_in_"):
            raise ValueError("Loaded models are missing n_features_in_ and cannot be validated")

        iforest_features = int(self._iforest.n_features_in_)
        rf_features = int(self._rf.n_features_in_)
        if iforest_features != rf_features:
            raise ValueError(
                "Model feature mismatch: isolation_forest expects "
                f"{iforest_features}, random_forest expects {rf_features}"
            )
        self._expected_feature_count = iforest_features

    def _validate_input_shape(self, features: np.ndarray) -> None:
        if features.ndim != 2:
            raise ValueError("Features must be a 2D numpy array")
        if self._expected_feature_count is None:
            raise RuntimeError("Model feature validation is incomplete")
        if features.shape[1] != self._expected_feature_count:
            raise ValueError(
                "Input feature mismatch: model expects "
                f"{self._expected_feature_count} features, received {features.shape[1]}"
            )

    @staticmethod
    def _verify_hash(path: Path, expected_hash: str) -> None:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_hash:
            raise ValueError(f"Model integrity check failed for {path.name}")
