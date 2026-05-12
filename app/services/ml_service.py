import logging
import json
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.ml.features.wazuh_feature_extractor import WazuhFeatureExtractor
from app.services.alert_service import AlertService
from app.services.ml_promotion_service import MLPromotionService
from app.services.ml_suppression_service import MLSuppressionService

logger = logging.getLogger(__name__)


class MLService:
    _feature_extractor = WazuhFeatureExtractor()
    _model_version: str = "cloud-api"
    _supported_decoder_scope = {"web-accesslog"}

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
        self._promotions = MLPromotionService()
        self._suppressions = MLSuppressionService()

    async def run_batch_inference(self, batch_size: int) -> Dict[str, int]:
        logs = await self._logs.fetch_batch(batch_size)
        if not logs:
            return {"processed": 0, "alerts": 0}

        processed_count = 0
        alerts_created = 0
        for log in logs:
            processed_count += 1
            log_id = log["_id"]
            suppression = await self._suppressions.resolve_suppression(log)
            if suppression:
                await self._logs.mark_ml_skipped(
                    log_id,
                    "suppressed_false_positive",
                    self._model_version,
                )
                continue
            skip_reason = self.get_skip_reason(log)
            if skip_reason:
                await self._logs.mark_ml_skipped(log_id, skip_reason, self._model_version)
                continue
            try:
                result, model_version = await self.infer_single_log(log)
            except Exception as exc:  # noqa: BLE001
                await self._logs.mark_ml_error(log_id, str(exc))
                logger.exception("Batch inference failed for log %s", log_id)
                continue

            await self._logs.mark_ml_done(log_id, result, model_version)

            if result["alert_type"] == "benign":
                continue

            severity = self.derive_alert_severity(result)
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

    @staticmethod
    def derive_alert_severity(result: Dict[str, Any]) -> str:
        alert_type = str(result.get("alert_type") or "").strip().lower()
        score_raw = result.get("score")
        score = float(score_raw) if isinstance(score_raw, (int, float)) else 0.0

        if alert_type == "known_attack":
            if score >= 0.85:
                return "high"
            if score >= 0.70:
                return "medium"
            return "low"

        if alert_type == "anomaly":
            if score >= 0.85:
                return "high"
            if score >= 0.70:
                return "medium"
            return "low"

        return "low"

    async def infer_logs(self, logs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
        features = self._feature_extractor.transform(logs)
        model_api_url = self.get_required_model_api_url(self._settings)
        results, model_version = await self._predict_with_cloud_model(model_api_url, features)
        promoted: List[Dict[str, Any]] = []
        for idx, result in enumerate(results):
            promoted.append(await self._apply_manual_promotion(logs[idx], result))
        return (promoted, model_version)

    async def infer_single_log(self, log: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        suppression = await self._suppressions.resolve_suppression(log)
        if suppression:
            return (
                {
                    "alert_type": "benign",
                    "classification": None,
                    "score": 0.0,
                    "rf_label": "0",
                    "if_used": False,
                    "raw_prediction": "SUPPRESSED_FALSE_POSITIVE",
                    "suppression_fingerprint": suppression.get("fingerprint"),
                },
                self._model_version,
            )
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
                    if health_url.endswith("/health"):
                        try:
                            body = response.json()
                        except ValueError:
                            return
                        expected = body.get("expected_feature_count")
                        current = len(cls._feature_extractor.FEATURE_NAMES)
                        if isinstance(expected, int) and expected != current:
                            logger.warning(
                                "Cloud model feature mismatch: cloud expects %s, backend produces %s. "
                                "Retrain/activate a model compatible with wazuh_native_v1.",
                                expected,
                                current,
                            )
                    return
                errors.append(f"{health_url} -> HTTP {response.status_code}")

        raise RuntimeError(
            "Cloud model API is not reachable or not healthy. "
            f"Base URL: {model_api_url}. Checks: {'; '.join(errors)}"
        )

    async def _predict_with_cloud_model(self, model_api_url: str, features) -> Tuple[List[Dict[str, Any]], str]:
        predict_url = f"{model_api_url.rstrip('/')}/predict"
        timeout = max(1, self._settings.model_api_timeout_seconds)
        results: List[Dict[str, Any]] = []
        resolved_model_version = self._model_version

        async with httpx.AsyncClient(timeout=timeout) as client:
            for feature_row in features:
                payload = feature_row.tolist()
                try:
                    prediction_payload = await self._request_cloud_prediction(client, predict_url, payload)
                except httpx.HTTPError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Cloud model API request failed: {exc}",
                    ) from exc
                prediction = prediction_payload["prediction"]
                model_version = prediction_payload.get("model_version")
                if model_version:
                    resolved_model_version = model_version
                mapped = self._map_cloud_prediction(prediction, prediction_payload)
                if model_version:
                    mapped["model_version"] = model_version
                results.append(mapped)
        return results, resolved_model_version

    async def _request_cloud_prediction(
        self,
        client: httpx.AsyncClient,
        predict_url: str,
        payload: List[float],
    ) -> Dict[str, Any]:
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
                if response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
                    detail_text = response.text[:500]
                    raise httpx.HTTPError(
                        "Cloud model rejected feature vector (422). "
                        "Likely feature-schema mismatch between backend and model. "
                        f"Response: {detail_text}"
                    )
                if response.status_code in {
                    status.HTTP_400_BAD_REQUEST,
                    status.HTTP_404_NOT_FOUND,
                    status.HTTP_405_METHOD_NOT_ALLOWED,
                    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
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

            prediction_payload = self._extract_prediction_payload(body)
            if prediction_payload.get("prediction"):
                return prediction_payload

        if last_http_error:
            raise last_http_error
        raise httpx.HTTPError("Cloud model API returned no usable prediction")

    @staticmethod
    def _extract_prediction_payload(body: Any) -> Dict[str, Any]:
        prediction = ""
        model_version = None
        details: Dict[str, Any] = {}
        if isinstance(body, dict):
            raw_version = body.get("model_version", body.get("version"))
            if isinstance(raw_version, str) and raw_version.strip():
                model_version = raw_version.strip()
            for key in ("prediction", "result", "label", "class"):
                value = body.get(key)
                if isinstance(value, str) and value.strip():
                    prediction = value.strip()
                    break
                if isinstance(value, (int, float)) and prediction == "":
                    prediction = str(value)
                    break
                if isinstance(value, dict):
                    nested_prediction = value.get("prediction")
                    if isinstance(nested_prediction, str) and nested_prediction.strip():
                        prediction = nested_prediction.strip()
                        details = value
                        break
                if isinstance(value, list) and value:
                    first = value[0]
                    if isinstance(first, str):
                        prediction = first.strip()
                        break
                    if isinstance(first, (int, float)) and prediction == "":
                        prediction = str(first)
                        break
        elif isinstance(body, list) and body:
            first = body[0]
            if isinstance(first, str):
                prediction = first.strip()
            elif isinstance(first, (int, float)):
                prediction = str(first)
        if isinstance(body, dict) and not details:
            for key in ("rf_pred", "rf_max_proba", "if_pred", "if_anomaly_score"):
                if key in body:
                    details[key] = body.get(key)
        return {"prediction": prediction, "model_version": model_version, **details}

    def _map_cloud_prediction(self, prediction: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
        payload = payload or {}
        raw_prediction = str(prediction or "").strip()
        normalized = raw_prediction.upper()
        rf_max_proba_raw = payload.get("rf_max_proba")
        if_anomaly_score_raw = payload.get("if_anomaly_score")
        rf_max_proba = (
            float(rf_max_proba_raw) if isinstance(rf_max_proba_raw, (int, float)) else None
        )
        if_anomaly_score = (
            float(if_anomaly_score_raw) if isinstance(if_anomaly_score_raw, (int, float)) else None
        )

        if normalized == "BENIGN":
            return {
                "alert_type": "benign",
                "classification": None,
                "score": 0.0,
                "rf_label": "0",
                "if_used": True,
                "raw_prediction": raw_prediction,
                "rf_max_proba": rf_max_proba,
                "if_anomaly_score": if_anomaly_score,
            }
        if normalized in {"UNKNOWN_ATTACK", "ANOMALY"}:
            return {
                "alert_type": "anomaly",
                "classification": None,
                "score": (
                    if_anomaly_score
                    if if_anomaly_score is not None
                    else self._settings.anomaly_score_threshold
                ),
                "rf_label": "0",
                "if_used": True,
                "raw_prediction": "ANOMALY",
                "rf_max_proba": rf_max_proba,
                "if_anomaly_score": if_anomaly_score,
            }
        prefix = "KNOWN_ATTACK_"
        if normalized.startswith(prefix):
            classification = raw_prediction[len(prefix):].strip() or None
            rf_label = classification or raw_prediction[len(prefix):].strip() or "1"
            return {
                "alert_type": "known_attack",
                "classification": classification,
                "score": rf_max_proba if rf_max_proba is not None else 1.0,
                "rf_label": rf_label,
                "if_used": False,
                "raw_prediction": raw_prediction,
                "rf_max_proba": rf_max_proba,
                "if_anomaly_score": if_anomaly_score,
            }
        logger.warning("Unexpected cloud prediction '%s'; treating as anomaly", prediction)
        return {
            "alert_type": "anomaly",
            "classification": None,
            "score": (
                if_anomaly_score
                if if_anomaly_score is not None
                else self._settings.anomaly_score_threshold
            ),
            "rf_label": "0",
            "if_used": True,
            "raw_prediction": raw_prediction,
            "rf_max_proba": rf_max_proba,
            "if_anomaly_score": if_anomaly_score,
        }

    def get_skip_reason(self, log: Dict[str, Any]) -> str | None:
        metadata = log.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        raw = metadata.get("raw_wazuh_payload")
        if not isinstance(raw, dict):
            return None
        decoder = raw.get("decoder")
        decoder_name = ""
        if isinstance(decoder, dict):
            decoder_name = str(decoder.get("name") or "").strip().lower()
        if decoder_name in self._supported_decoder_scope:
            return None
        return "decoder_not_supported_v1"

    async def _apply_manual_promotion(self, log: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        if result.get("alert_type") != "anomaly":
            return result
        match = await self._promotions.resolve_manual_promotion(log)
        if not match:
            return result
        promoted = dict(result)
        promoted["alert_type"] = "known_attack"
        promoted["classification"] = match.get("classification")
        promoted["score"] = 1.0
        promoted["promotion_source"] = "manual_fingerprint"
        promoted["fingerprint"] = match.get("fingerprint")
        return promoted
