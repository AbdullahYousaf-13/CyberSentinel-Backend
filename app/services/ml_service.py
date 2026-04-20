import logging
import json
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.ml.features.feature_extractor import FeatureExtractor
from app.services.alert_service import AlertService

logger = logging.getLogger(__name__)


class MLService:
    _feature_extractor = FeatureExtractor()
    _model_version: str = "cloud-api"

    @classmethod
    async def initialize(cls, settings: Settings) -> None:
        model_api_url = cls.get_required_model_api_url(settings)
        await cls.validate_cloud_model_reachable(
            model_api_url, settings.model_api_timeout_seconds
        )
        cls._model_version = "cloud-api"
        logger.info("Cloud model API is ready at %s", model_api_url)

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logs = LogRepository()
        self._alerts = AlertService()

    async def run_batch_inference(self, batch_size: int) -> Dict[str, int]:
        logs = await self._logs.fetch_batch(batch_size)
        if not logs:
            return {"processed": 0, "alerts": 0}

        processed_count = 0
        alerts_created = 0
        for log in logs:
            processed_count += 1
            log_id = log["_id"]
            try:
                result, model_version = await self.infer_single_log(log)
            except Exception as exc:  # noqa: BLE001
                await self._logs.mark_ml_error(log_id, str(exc))
                logger.exception("Batch inference failed for log %s", log_id)
                continue

            await self._logs.mark_ml_done(log_id, result, model_version)

            if result["alert_type"] == "benign":
                continue

            severity = "high" if result["alert_type"] == "known_attack" else "medium"
            await self._alerts.create_or_get_alert(
                log_id=str(log_id),
                alert_type=result["alert_type"],
                severity=severity,
                model_version=model_version,
                metadata={
                    "source": log.get("source"),
                    "message": (log.get("message") or "")[:200],
                },
                classification=result.get("classification"),
                anomaly_score=float(result.get("score", 0.0)),
            )
            alerts_created += 1
        return {"processed": processed_count, "alerts": alerts_created}

    async def infer_logs(self, logs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
        features = self._feature_extractor.transform(logs)
        model_api_url = self.get_required_model_api_url(self._settings)
        return (
            await self._predict_with_cloud_model(model_api_url, features),
            self._model_version,
        )

    async def infer_single_log(self, log: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        results, model_version = await self.infer_logs([log])
        if not results:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Inference result is empty")
        return results[0], model_version

    @staticmethod
    def get_required_model_api_url(settings: Settings) -> str:
        model_api_url = (settings.model_api_url or "").strip()
        if not model_api_url:
            raise RuntimeError(
                "MODEL_API_URL is required in cloud-only mode. "
                "Example: http://127.0.0.1:8010"
            )

        parsed = urlparse(model_api_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError(
                "MODEL_API_URL must be an absolute http(s) URL. "
                f"Received: {model_api_url}"
            )
        return model_api_url.rstrip("/")

    @classmethod
    async def validate_cloud_model_reachable(
        cls, model_api_url: str, timeout_seconds: int
    ) -> None:
        timeout = max(1, timeout_seconds)
        health_candidates = [f"{model_api_url}/health", f"{model_api_url}/"]
        errors: List[str] = []

        async with httpx.AsyncClient(timeout=timeout) as client:
            for health_url in health_candidates:
                try:
                    response = await client.get(health_url)
                except httpx.HTTPError as exc:
                    errors.append(
                        f"{health_url} -> request failed: {exc.__class__.__name__}: {exc}"
                    )
                    continue

                if response.status_code < 400:
                    return
                errors.append(f"{health_url} -> HTTP {response.status_code}")

        raise RuntimeError(
            "Cloud model API is not reachable or not healthy. "
            f"Base URL: {model_api_url}. Checks: {'; '.join(errors)}"
        )

    async def _predict_with_cloud_model(self, model_api_url: str, features) -> List[Dict[str, Any]]:
        predict_url = f"{model_api_url.rstrip('/')}/predict"
        timeout = max(1, self._settings.model_api_timeout_seconds)
        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=timeout) as client:
            for feature_row in features:
                payload = feature_row.tolist()
                try:
                    prediction = await self._request_cloud_prediction(client, predict_url, payload)
                except httpx.HTTPError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Cloud model API request failed: {exc}",
                    ) from exc
                results.append(self._map_cloud_prediction(prediction))
        return results

    async def _request_cloud_prediction(
        self,
        client: httpx.AsyncClient,
        predict_url: str,
        payload: List[float],
    ) -> str:
        attempts = [
            ("json-list", {"json": payload}),
            ("json-object-sample", {"json": {"sample": payload}}),
            ("json-object-features", {"json": {"features": payload}}),
            ("json-object-data", {"json": {"data": payload}}),
            # Some deployments expose `sample: list` as form-data and need repeated `sample` fields.
            ("form-repeated-sample", {"data": [("sample", str(v)) for v in payload]}),
            ("form-json-sample", {"data": {"sample": json.dumps(payload)}}),
        ]

        last_http_error: httpx.HTTPStatusError | None = None
        for name, kwargs in attempts:
            response = await client.post(predict_url, **kwargs)
            if response.status_code >= 400:
                if response.status_code in {
                    status.HTTP_400_BAD_REQUEST,
                    status.HTTP_404_NOT_FOUND,
                    status.HTTP_405_METHOD_NOT_ALLOWED,
                    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                }:
                    logger.debug(
                        "Cloud prediction attempt %s failed with %s: %s",
                        name,
                        response.status_code,
                        response.text[:300],
                    )
                    try:
                        response.raise_for_status()
                    except httpx.HTTPStatusError as exc:
                        last_http_error = exc
                    continue
                response.raise_for_status()

            try:
                body = response.json()
            except ValueError:
                logger.debug("Cloud prediction attempt %s returned non-JSON body", name)
                continue

            prediction = self._extract_prediction_value(body)
            if prediction:
                return prediction

        if last_http_error:
            raise last_http_error
        raise httpx.HTTPError("Cloud model API returned no usable prediction")

    @staticmethod
    def _extract_prediction_value(body: Any) -> str:
        if isinstance(body, dict):
            for key in ("prediction", "result", "label", "class"):
                value = body.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
                if isinstance(value, (int, float)):
                    return str(value)
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, str):
                        return first.strip()
                    if isinstance(first, (int, float)):
                        return str(first)
            return ""
        if isinstance(body, list) and body:
            first = body[0]
            if isinstance(first, str):
                return first.strip()
            if isinstance(first, (int, float)):
                return str(first)
        return ""

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
