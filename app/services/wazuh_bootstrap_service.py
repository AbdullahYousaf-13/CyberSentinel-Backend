from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from app.db.repositories.alert_repository import AlertRepository
from app.db.repositories.log_repository import LogRepository
from app.ml.bootstrap import WazuhBootstrapDatasetBuilder
from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.alert_service import AlertService
from app.services.ml_promotion_service import MLPromotionService
from app.services.ml_suppression_service import MLSuppressionService


class WazuhBootstrapService:
    MAX_SCAN_LIMIT = 20000

    def __init__(self) -> None:
        self._logs = LogRepository()
        self._alerts = AlertRepository()
        self._alert_service = AlertService()
        self._engineer = WazuhFamilyFeatureEngineer()
        self._builder = WazuhBootstrapDatasetBuilder(self._engineer)
        self._promotions = MLPromotionService()
        self._suppressions = MLSuppressionService()

    async def preview_dataset(
        self,
        model_family: str,
        *,
        scan_limit: int = 5000,
        preview_limit: int = 100,
        include_feedback_overrides: bool = True,
        min_class_support: int = 10,
    ) -> Dict[str, Any]:
        normalized_family = self._normalize_family(model_family)
        limit = max(1, min(int(scan_limit), self.MAX_SCAN_LIMIT))
        preview_rows = max(1, min(int(preview_limit), limit))
        logs = await self._load_family_logs(normalized_family, limit)
        built = self._builder.build(
            logs,
            normalized_family,
            reason="bootstrap_preview_only",
            min_class_support=min_class_support,
            preview_limit=preview_rows,
            include_feedback_overrides=include_feedback_overrides,
        )
        built.pop("training_payload", None)
        return built

    async def build_training_payload(
        self,
        model_family: str,
        *,
        scan_limit: int = 5000,
        min_class_support: int = 10,
        include_feedback_overrides: bool = True,
    ) -> Dict[str, Any]:
        normalized_family = self._normalize_family(model_family)
        limit = max(1, min(int(scan_limit), self.MAX_SCAN_LIMIT))
        logs = await self._load_family_logs(normalized_family, limit)
        built = self._builder.build(
            logs,
            normalized_family,
            reason=f"bootstrap_{normalized_family}_seed_dataset",
            min_class_support=min_class_support,
            preview_limit=0,
            include_feedback_overrides=include_feedback_overrides,
        )
        payload = built.pop("training_payload")
        payload["dataset_summary"] = {
            "scanned_logs": built["scanned_logs"],
            "usable_samples": built["usable_samples"],
            "feedback_override_count": built["feedback_override_count"],
            "label_distribution": built["label_distribution"],
            "raw_label_distribution": built["raw_label_distribution"],
            "verdict_distribution": built["verdict_distribution"],
            "thresholds": built["thresholds"],
        }
        return payload

    async def import_reviews(
        self,
        model_family: str,
        items: List[Dict[str, Any]],
        *,
        reviewed_by: str,
    ) -> Dict[str, Any]:
        normalized_family = self._normalize_family(model_family)
        applied = 0
        skipped = 0
        failed = 0
        errors: List[Dict[str, str]] = []

        for item in items:
            log_id = str(item.get("log_id") or "").strip()
            classification = str(item.get("review_classification") or item.get("classification") or "").strip()
            notes = str(item.get("notes") or item.get("heuristic_reason") or "").strip() or None
            try:
                verdict = self._normalize_verdict(item.get("review_verdict") or item.get("verdict"))
            except ValueError as exc:
                failed += 1
                errors.append({"log_id": log_id, "error": str(exc)})
                continue

            if verdict == "skip":
                skipped += 1
                continue
            if not log_id:
                failed += 1
                errors.append({"log_id": "", "error": "log_id is required"})
                continue

            try:
                log_doc = await self._logs.get_by_id(log_id)
            except Exception:  # noqa: BLE001
                log_doc = None
            if not log_doc:
                failed += 1
                errors.append({"log_id": log_id, "error": "Log not found"})
                continue

            actual_family = self._engineer.family_for_log(log_doc)
            if actual_family != normalized_family:
                failed += 1
                errors.append(
                    {
                        "log_id": log_id,
                        "error": f"Log belongs to model family {actual_family or 'unknown'}, expected {normalized_family}",
                    }
                )
                continue

            try:
                await self._apply_review(
                    log_id=log_id,
                    log_doc=log_doc,
                    verdict=verdict,
                    classification=classification,
                    reviewed_by=reviewed_by,
                    notes=notes,
                )
            except ValueError as exc:
                failed += 1
                errors.append({"log_id": log_id, "error": str(exc)})
                continue

            applied += 1

        return {
            "model_family": normalized_family,
            "applied": applied,
            "skipped": skipped,
            "failed": failed,
            "errors": errors[:50],
        }

    async def _apply_review(
        self,
        *,
        log_id: str,
        log_doc: Dict[str, Any],
        verdict: str,
        classification: str,
        reviewed_by: str,
        notes: str | None,
    ) -> None:
        linked_alert = await self._alerts.get_alert_by_log_id(log_id)
        if verdict == "false_positive":
            if linked_alert:
                await self._alert_service.mark_false_positive(
                    alert_id=str(linked_alert["_id"]),
                    reviewed_by=reviewed_by,
                    notes=notes,
                )
                return
            await self._apply_false_positive_without_alert(log_id, log_doc, reviewed_by, notes)
            return

        if verdict == "confirmed_known_attack":
            if not classification:
                raise ValueError("review_classification is required for confirmed_known_attack")
            if linked_alert:
                await self._alert_service.confirm_known_attack(
                    alert_id=str(linked_alert["_id"]),
                    classification=classification,
                    confirmed_by=reviewed_by,
                    notes=notes,
                )
                return
            await self._apply_known_attack_without_alert(log_id, log_doc, classification, reviewed_by, notes)
            return

        if verdict == "confirmed_benign":
            await self._apply_confirmed_benign(log_id, linked_alert, reviewed_by, notes)
            return

        raise ValueError(f"Unsupported review verdict '{verdict}'")

    async def _apply_false_positive_without_alert(
        self,
        log_id: str,
        log_doc: Dict[str, Any],
        reviewed_by: str,
        notes: str | None,
    ) -> None:
        fingerprint = await self._suppressions.mark_false_positive(log_doc, created_by=reviewed_by, notes=notes)
        feedback = {
            "verdict": "false_positive",
            "by": reviewed_by,
            "at": datetime.utcnow(),
            "notes": notes,
            "fingerprint": fingerprint,
            "source": "bulk_review_import",
        }
        await self._logs.update_fields_by_id(
            log_id,
            {
                "metadata.feedback": feedback,
                "metadata.suppression": {
                    "fingerprint": fingerprint,
                    "active": True,
                    "reason": "false_positive",
                },
            },
        )

    async def _apply_known_attack_without_alert(
        self,
        log_id: str,
        log_doc: Dict[str, Any],
        classification: str,
        reviewed_by: str,
        notes: str | None,
    ) -> None:
        fingerprint = await self._promotions.register_manual_promotion(
            log_doc=log_doc,
            classification=classification,
            created_by=reviewed_by,
            notes=notes,
        )
        normalized = self._promotions.validate_label(
            self._promotions.normalize_classification_label(classification)
        )
        feedback = {
            "verdict": "confirmed_known_attack",
            "by": reviewed_by,
            "at": datetime.utcnow(),
            "notes": notes,
            "fingerprint": fingerprint,
            "source": "bulk_review_import",
        }
        await self._logs.update_fields_by_id(
            log_id,
            {
                "ml_result.alert_type": "known_attack",
                "ml_result.classification": normalized,
                "ml_result.score": 1.0,
                "metadata.feedback": feedback,
                "metadata.manual_promotion": {
                    "fingerprint": fingerprint,
                    "classification": normalized,
                    "confirmed_by": reviewed_by,
                    "notes": notes,
                    "confirmed_at": datetime.utcnow(),
                },
            },
        )

    async def _apply_confirmed_benign(
        self,
        log_id: str,
        linked_alert: Dict[str, Any] | None,
        reviewed_by: str,
        notes: str | None,
    ) -> None:
        feedback = {
            "verdict": "confirmed_benign",
            "by": reviewed_by,
            "at": datetime.utcnow(),
            "notes": notes,
            "source": "bulk_review_import",
        }
        await self._logs.update_fields_by_id(log_id, {"metadata.feedback": feedback})
        if linked_alert:
            await self._alerts.update_alert_fields(str(linked_alert["_id"]), {"metadata.feedback": feedback})

    async def _load_family_logs(self, model_family: str, limit: int) -> List[Dict[str, Any]]:
        decoders = [
            decoder
            for decoder, family in self._engineer.DECODER_TO_FAMILY.items()
            if family == model_family
        ]
        filters: Dict[str, Any] = {
            "metadata.raw_wazuh_payload": {"$exists": True},
        }
        if decoders:
            filters["metadata.raw_wazuh_payload.decoder.name"] = {"$in": decoders}
        return await self._logs.list_logs(limit=limit, offset=0, filters=filters)

    def _normalize_family(self, model_family: str) -> str:
        normalized = str(model_family or "").strip().lower()
        if normalized not in self._engineer.SCHEMA_BY_FAMILY:
            supported = ", ".join(sorted(self._engineer.SCHEMA_BY_FAMILY))
            raise ValueError(f"Unsupported model family '{model_family}'. Supported families: {supported}")
        return normalized

    @staticmethod
    def _normalize_verdict(value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {"confirmed_benign", "false_positive", "confirmed_known_attack", "skip"}:
            return normalized
        raise ValueError(f"Unsupported review verdict '{value}'")
