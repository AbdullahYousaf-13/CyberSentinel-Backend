import logging
from typing import Dict, List

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
            logger.warning("Model registry not initialized; inference will be unavailable until retraining.")

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logs = LogRepository()
        self._alerts = AlertService()

    async def run_batch_inference(self, batch_size: int) -> Dict[str, int]:
        if self._engine is None:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Models not initialized")
        logs = await self._logs.fetch_batch(batch_size)
        if not logs:
            return {"processed": 0, "alerts": 0}

        features = self._feature_extractor.transform(logs)
        results = self._engine.predict(features, self._settings.anomaly_score_threshold)["results"]

        alerts_created = 0
        for log, result in zip(logs, results):
            if result["alert_type"] == "benign":
                continue
            severity = "high" if result["alert_type"] == "known_attack" else "medium"
            await self._alerts.create_alert(
                log_id=str(log["_id"]),
                alert_type=result["alert_type"],
                severity=severity,
                model_version=self._model_version,
                metadata={"source": log.get("source"), "message": log.get("message")[:200]},
                classification=result.get("classification"),
                anomaly_score=float(result.get("score", 0.0)),
            )
            alerts_created += 1
        return {"processed": len(logs), "alerts": alerts_created}

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
