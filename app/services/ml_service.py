import json
import logging
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.ml.bootstrap import WazuhBootstrapDatasetBuilder
from app.ml.features.feature_extractor import FeatureExtractor
from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.alert_service import AlertService
from app.services.ml_promotion_service import MLPromotionService
from app.services.ml_suppression_service import MLSuppressionService

logger = logging.getLogger(__name__)


class MLService:
    _legacy_feature_extractor = FeatureExtractor()
    _wazuh_feature_engineer = WazuhFamilyFeatureEngineer()
    _wazuh_rules_builder = WazuhBootstrapDatasetBuilder(_wazuh_feature_engineer)
    _model_version: str = "cloud-api"
    _active_family_versions: Dict[str, str] = {}
    _catalog_checked_at: float = 0.0
    _catalog_ttl_seconds: float = 30.0

    @classmethod
    async def initialize(cls, settings: Settings) -> None:
        model_api_url = cls.get_required_model_api_url(settings)
        await cls.validate_cloud_model_reachable(model_api_url, settings.model_api_timeout_seconds)
        await cls._refresh_model_catalog(settings, force=True)
        logger.info("Cloud model API is ready at %s", model_api_url)

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._logs = LogRepository()
        self._alerts = AlertService()
        self._promotions = MLPromotionService()
        self._suppressions = MLSuppressionService()

    async def refresh_model_catalog(self, force: bool = False) -> None:
        await self._refresh_model_catalog(self._settings, force=force)

    async def run_batch_inference(self, batch_size: int) -> Dict[str, int]:
        await self.refresh_model_catalog()
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
            if skip_reason == "rules_only_family_not_trained":
                result, model_version = self.infer_rules_only(log)
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
                        "model_family": result.get("model_family"),
                        "feature_schema_version": result.get("feature_schema_version"),
                        "classification_source": result.get("classification_source"),
                        "rules_reason": result.get("rules_reason"),
                    },
                    classification=result.get("classification"),
                    anomaly_score=float(result.get("score", 0.0)),
                )
                alerts_created += 1
                continue
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

            severity = "high" if result["alert_type"] == "known_attack" else "medium"
            await self._alerts.create_or_get_alert(
                log_id=str(log_id),
                alert_type=result["alert_type"],
                severity=severity,
                model_version=model_version,
                metadata={
                    "source": log.get("source"),
                    "message": (log.get("message") or "")[:200],
                    "model_family": result.get("model_family"),
                    "feature_schema_version": result.get("feature_schema_version"),
                },
                classification=result.get("classification"),
                anomaly_score=float(result.get("score", 0.0)),
            )
            alerts_created += 1
        return {"processed": processed_count, "alerts": alerts_created}

    async def infer_logs(self, logs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
        await self.refresh_model_catalog()
        model_api_url = self.get_required_model_api_url(self._settings)
        results, model_version = await self._predict_with_cloud_model(model_api_url, logs)
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
                    "decision_score": 0.0,
                    "classification_confidence": None,
                    "novelty_score": None,
                    "rf_label": "0",
                    "if_used": False,
                    "raw_prediction": "SUPPRESSED_FALSE_POSITIVE",
                    "suppression_fingerprint": suppression.get("fingerprint"),
                    "model_family": None,
                    "feature_schema_version": None,
                },
                self._model_version,
            )
        skip_reason = self.get_skip_reason(log)
        if skip_reason == "rules_only_family_not_trained":
            result, model_version = self.infer_rules_only(log)
            return result, model_version
        results, model_version = await self.infer_logs([log])
        if not results:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Inference result is empty")
        return results[0], model_version

    def infer_rules_only(self, log: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        classified = self._wazuh_rules_builder.classify_log(log, include_feedback_overrides=True)
        family = classified.get("model_family")
        model_version = f"rules-only-{family}-v1" if family else "rules-only"
        alert_type = str(classified.get("alert_type") or "benign").strip().lower()
        classification = classified.get("classification")
        decision_score = 1.0 if alert_type == "known_attack" else 0.0
        return (
            {
                "alert_type": alert_type,
                "classification": classification if isinstance(classification, str) and classification.strip() else None,
                "score": decision_score,
                "decision_score": decision_score,
                "classification_confidence": decision_score if alert_type == "known_attack" else None,
                "novelty_score": None,
                "rf_label": "0",
                "if_used": False,
                "raw_prediction": classified,
                "model_family": family,
                "feature_schema_version": classified.get("feature_schema_version"),
                "classification_source": "rules_only",
                "rules_reason": classified.get("reason"),
                "model_version": model_version,
            },
            model_version,
        )

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

    @classmethod
    async def _refresh_model_catalog(cls, settings: Settings, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - cls._catalog_checked_at) < cls._catalog_ttl_seconds:
            return

        model_api_url = cls.get_required_model_api_url(settings)
        timeout = max(1, settings.model_api_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{model_api_url}/health")
            response.raise_for_status()
            body = response.json()
        active_families = body.get("active_families", body.get("active_versions"))
        normalized: Dict[str, str] = {}
        if isinstance(active_families, dict):
            for family, version in active_families.items():
                if not isinstance(family, str) or not isinstance(version, str):
                    continue
                family_key = family.strip().lower()
                version_value = version.strip()
                if family_key and version_value:
                    normalized[family_key] = version_value
        cls._active_family_versions = normalized
        if len(normalized) == 1:
            cls._model_version = next(iter(normalized.values()))
        else:
            cls._model_version = "cloud-api"
        cls._catalog_checked_at = now

    async def _predict_with_cloud_model(self, model_api_url: str, logs: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
        predict_url = f"{model_api_url.rstrip('/')}/predict"
        timeout = max(1, self._settings.model_api_timeout_seconds)
        results: List[Dict[str, Any]] = []
        resolved_model_version = self._model_version

        async with httpx.AsyncClient(timeout=timeout) as client:
            for log in logs:
                request_descriptor = self._build_prediction_request(log)
                try:
                    prediction_payload = await self._request_cloud_prediction(client, predict_url, request_descriptor)
                except httpx.HTTPError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_502_BAD_GATEWAY,
                        detail=f"Cloud model API request failed: {exc}",
                    ) from exc
                prediction = prediction_payload["prediction"]
                model_version = prediction_payload.get("model_version")
                mapped = self._map_cloud_prediction(prediction)
                if model_version:
                    resolved_model_version = model_version
                    mapped.setdefault("model_version", model_version)
                elif isinstance(mapped.get("model_version"), str) and mapped["model_version"]:
                    resolved_model_version = str(mapped["model_version"])
                results.append(mapped)
        return results, resolved_model_version

    def _build_prediction_request(self, log: Dict[str, Any]) -> Dict[str, Any]:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict) and isinstance(metadata.get("raw_wazuh_payload"), dict):
            structured = self._wazuh_feature_engineer.build_prediction_payload(log)
            if structured:
                return {"mode": "structured", "body": structured}
        features = self._legacy_feature_extractor.transform([log])
        return {"mode": "legacy", "body": features[0].tolist()}

    async def _request_cloud_prediction(
        self,
        client: httpx.AsyncClient,
        predict_url: str,
        request_descriptor: Dict[str, Any],
    ) -> Dict[str, Any]:
        if request_descriptor.get("mode") == "structured":
            response = await client.post(predict_url, json=request_descriptor["body"])
            response.raise_for_status()
            return self._extract_prediction_payload(response.json())

        payload = request_descriptor["body"]
        attempts = [
            ("json-list", {"json": payload}),
            ("json-object-sample", {"json": {"sample": payload}}),
            ("json-object-features", {"json": {"features": payload}}),
            ("json-object-data", {"json": {"data": payload}}),
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

            prediction_payload = self._extract_prediction_payload(body)
            if prediction_payload.get("prediction") is not None:
                return prediction_payload

        if last_http_error:
            raise last_http_error
        raise httpx.HTTPError("Cloud model API returned no usable prediction")

    @staticmethod
    def _extract_prediction_payload(body: Any) -> Dict[str, Any]:
        prediction: Any = None
        model_version = None
        if isinstance(body, dict):
            raw_version = body.get("model_version", body.get("version"))
            if isinstance(raw_version, str) and raw_version.strip():
                model_version = raw_version.strip()
            prediction_value = body.get("prediction", body.get("result", body.get("label", body.get("class"))))
            if isinstance(prediction_value, dict):
                prediction = dict(prediction_value)
                if model_version and not prediction.get("model_version"):
                    prediction["model_version"] = model_version
                return {"prediction": prediction, "model_version": model_version}
            if isinstance(prediction_value, str) and prediction_value.strip():
                prediction = prediction_value.strip()
            elif isinstance(prediction_value, (int, float)):
                prediction = str(prediction_value)
            elif isinstance(prediction_value, list) and prediction_value:
                first = prediction_value[0]
                if isinstance(first, dict):
                    prediction = dict(first)
                    if model_version and not prediction.get("model_version"):
                        prediction["model_version"] = model_version
                elif isinstance(first, str):
                    prediction = first.strip()
                elif isinstance(first, (int, float)):
                    prediction = str(first)
        elif isinstance(body, list) and body:
            first = body[0]
            if isinstance(first, str):
                prediction = first.strip()
            elif isinstance(first, (int, float)):
                prediction = str(first)
            elif isinstance(first, dict):
                prediction = dict(first)
        return {"prediction": prediction, "model_version": model_version}

    def _map_cloud_prediction(self, prediction: Any) -> Dict[str, Any]:
        if isinstance(prediction, dict):
            return self._map_structured_prediction(prediction)
        return self._map_legacy_prediction(str(prediction or "").strip())

    def _map_structured_prediction(self, prediction: Dict[str, Any]) -> Dict[str, Any]:
        alert_type = str(prediction.get("alert_type") or "benign").strip().lower()
        if alert_type not in {"benign", "known_attack", "anomaly"}:
            alert_type = "benign"
        classification = prediction.get("classification")
        classification = str(classification).strip() if isinstance(classification, str) and classification.strip() else None
        decision_score = self._safe_float(prediction.get("decision_score"), 0.0)
        classification_confidence = self._safe_float(prediction.get("classification_confidence"), None)
        novelty_score = self._safe_float(prediction.get("novelty_score"), None)
        return {
            "alert_type": alert_type,
            "classification": classification,
            "score": decision_score,
            "decision_score": decision_score,
            "classification_confidence": classification_confidence,
            "novelty_score": novelty_score,
            "rf_label": prediction.get("rf_label", "0"),
            "if_used": novelty_score is not None,
            "raw_prediction": prediction.get("raw_prediction", prediction),
            "model_family": prediction.get("model_family"),
            "feature_schema_version": prediction.get("feature_schema_version"),
            "model_version": prediction.get("model_version"),
        }

    def _map_legacy_prediction(self, prediction: str) -> Dict[str, Any]:
        raw_prediction = str(prediction or "").strip()
        normalized = raw_prediction.upper()
        if normalized == "BENIGN":
            return {
                "alert_type": "benign",
                "classification": None,
                "score": 0.0,
                "decision_score": 0.0,
                "classification_confidence": None,
                "novelty_score": None,
                "rf_label": "0",
                "if_used": True,
                "raw_prediction": raw_prediction,
                "model_family": None,
                "feature_schema_version": None,
            }
        if normalized in {"UNKNOWN_ATTACK", "ANOMALY"}:
            return {
                "alert_type": "anomaly",
                "classification": None,
                "score": self._settings.anomaly_score_threshold,
                "decision_score": self._settings.anomaly_score_threshold,
                "classification_confidence": None,
                "novelty_score": self._settings.anomaly_score_threshold,
                "rf_label": "0",
                "if_used": True,
                "raw_prediction": "ANOMALY",
                "model_family": None,
                "feature_schema_version": None,
            }
        prefix = "KNOWN_ATTACK_"
        if normalized.startswith(prefix):
            classification = raw_prediction[len(prefix):].strip() or None
            rf_label = classification or raw_prediction[len(prefix):].strip() or "1"
            return {
                "alert_type": "known_attack",
                "classification": classification,
                "score": 1.0,
                "decision_score": 1.0,
                "classification_confidence": 1.0,
                "novelty_score": None,
                "rf_label": rf_label,
                "if_used": False,
                "raw_prediction": raw_prediction,
                "model_family": None,
                "feature_schema_version": None,
            }
        logger.warning("Unexpected cloud prediction '%s'; treating as anomaly", prediction)
        return {
            "alert_type": "anomaly",
            "classification": None,
            "score": self._settings.anomaly_score_threshold,
            "decision_score": self._settings.anomaly_score_threshold,
            "classification_confidence": None,
            "novelty_score": self._settings.anomaly_score_threshold,
            "rf_label": "0",
            "if_used": True,
            "raw_prediction": raw_prediction,
            "model_family": None,
            "feature_schema_version": None,
        }

    def get_skip_reason(self, log: Dict[str, Any]) -> str | None:
        metadata = log.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        raw = metadata.get("raw_wazuh_payload")
        if not isinstance(raw, dict):
            return None
        family = self._wazuh_feature_engineer.family_for_log(log)
        if not family:
            return "model_family_unsupported"
        if family not in self._active_family_versions:
            return "rules_only_family_not_trained"
        return None

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
        promoted["decision_score"] = 1.0
        promoted["classification_confidence"] = 1.0
        promoted["promotion_source"] = "manual_fingerprint"
        promoted["fingerprint"] = match.get("fingerprint")
        return promoted

    @staticmethod
    def _safe_float(value: Any, default: float | None) -> float | None:
        if value is None:
            return default
        try:
            return float(value)
        except Exception:  # noqa: BLE001
            return default
