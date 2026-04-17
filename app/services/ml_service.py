import logging
from typing import Any, Dict, List

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.ml.features.feature_extractor import FeatureExtractor
from app.ml.inference.inference_engine import InferenceEngine
from app.ml.retraining.retraining_manager import RetrainingManager
from app.ml.training.training_service import train_models
from app.services.alert_service import AlertService

logger = logging.getLogger(__name__)


class MLService:
    _engine: InferenceEngine = None
    _feature_extractor = FeatureExtractor()
    _model_version: str = ""

    @classmethod
    async def initialize(cls, settings: Settings) -> None:
        manager = RetrainingManager(settings.model_dir)
        try:
            cls._model_version = manager.get_active_version()
            cls._engine = InferenceEngine(settings.model_dir, settings.model_integrity_required)
            cls._engine.load_version(cls._model_version)
        except FileNotFoundError:
            if settings.model_api_url:
                logger.info("Model registry not initialized; using external model API at %s", settings.model_api_url)
            else:
                logger.warning("Model registry not initialized; inference will be unavailable until retraining.")

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logs = LogRepository()
        self._alerts = AlertService()

    async def run_batch_inference(self, batch_size: int) -> Dict[str, int]:
        logs = await self._logs.fetch_batch(batch_size)
        if not logs:
            return {"processed": 0, "alerts": 0}

        features = self._feature_extractor.transform(logs)
        model_api_url = (self._settings.model_api_url or "").strip()
        if model_api_url:
            results = await self._predict_with_cloud_model(model_api_url, features)
            model_version = "cloud-api"
        else:
            if self._engine is None:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Models not initialized")
            results = self._engine.predict(features, self._settings.anomaly_score_threshold)["results"]
            model_version = self._model_version

        alerts_created = 0
        for log, result in zip(logs, results):
            if result["alert_type"] == "benign":
                continue
            severity = "high" if result["alert_type"] == "known_attack" else "medium"
            await self._alerts.create_alert(
                log_id=str(log["_id"]),
                alert_type=result["alert_type"],
                severity=severity,
                model_version=model_version,
                metadata={"source": log.get("source"), "message": log.get("message")[:200]},
                classification=result.get("classification"),
                anomaly_score=float(result.get("score", 0.0)),
            )
            alerts_created += 1
        return {"processed": len(logs), "alerts": alerts_created}

    async def _predict_with_cloud_model(self, model_api_url: str, features) -> List[Dict[str, Any]]:
        predict_url = f"{model_api_url.rstrip('/')}/predict"
        timeout = max(1, self._settings.model_api_timeout_seconds)
        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=timeout) as client:
            for feature_row in features:
                payload = feature_row.tolist()
                try:
                    response = await client.post(predict_url, json=payload)
                    if response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
                        # Backward compatibility for APIs that expect {"sample": [...]}
                        response = await client.post(predict_url, json={"sample": payload})
                    response.raise_for_status()
                    prediction = str(response.json().get("prediction", "")).strip()
                except httpx.HTTPError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Cloud model API request failed: {exc}",
                    ) from exc
                results.append(self._map_cloud_prediction(prediction))
        return results

    def _map_cloud_prediction(self, prediction: str) -> Dict[str, Any]:
        normalized = prediction.upper()
        if normalized == "BENIGN":
            return {"alert_type": "benign", "classification": None, "score": 0.0}
        if normalized == "UNKNOWN_ATTACK":
            return {
                "alert_type": "anomaly",
                "classification": None,
                "score": self._settings.anomaly_score_threshold,
            }
        prefix = "KNOWN_ATTACK_"
        if normalized.startswith(prefix):
            classification = prediction[len(prefix):] or None
            return {"alert_type": "known_attack", "classification": classification, "score": 1.0}
        logger.warning("Unexpected cloud prediction '%s'; treating as anomaly", prediction)
        return {
            "alert_type": "anomaly",
            "classification": prediction or None,
            "score": self._settings.anomaly_score_threshold,
        }

    def retrain_models(self, features, labels, reason: str) -> str:
        if features is None or labels is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing training data")
        iforest, rf = train_models(features, labels)
        manager = RetrainingManager(self._settings.model_dir)
        version = manager.save_new_version(iforest, rf, reason)
        self._model_version = version
        if self._engine is None:
            self._engine = InferenceEngine(self._settings.model_dir, self._settings.model_integrity_required)
        self._engine.load_version(version)
        logger.info("Retrained models and activated version %s", version)
        return version

    def rollback(self, target_version: str) -> None:
        manager = RetrainingManager(self._settings.model_dir)
        manager.rollback(target_version)
        self._model_version = target_version
        self._engine.load_version(target_version)
