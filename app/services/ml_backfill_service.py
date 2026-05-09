import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.config import Settings
from app.db.repositories.alert_repository import AlertRepository
from app.db.repositories.backfill_job_repository import BackfillJobRepository
from app.db.repositories.log_repository import LogRepository
from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.alert_service import AlertService
from app.services.ml_service import MLService

_backfill_lock = asyncio.Lock()
_running_backfill_job_id: Optional[str] = None


class MLBackfillService:
    MAX_SCAN_LIMIT = 50000

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jobs = BackfillJobRepository()
        self._logs = LogRepository()
        self._alerts = AlertRepository()
        self._alert_service = AlertService()
        self._engineer = WazuhFamilyFeatureEngineer()
        self._ml = MLService(settings)

    async def create_job(
        self,
        *,
        reason: str,
        requested_by: str,
        model_family: str,
        scan_limit: int = 20000,
    ) -> str:
        global _running_backfill_job_id
        async with _backfill_lock:
            if _running_backfill_job_id:
                raise RuntimeError("Another backfill job is already running")
            normalized_family = self._normalize_model_family(model_family)
            payload = {
                "status": "queued",
                "reason": reason.strip()[:300],
                "requested_by": requested_by,
                "model_family": normalized_family,
                "scan_limit": max(1, min(int(scan_limit), self.MAX_SCAN_LIMIT)),
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "result": {},
                "error": None,
            }
            job_id = await self._jobs.create_job(payload)
            _running_backfill_job_id = job_id
            asyncio.create_task(
                self._run_job(job_id, normalized_family, payload["scan_limit"]),
                name=f"ml-backfill-{job_id}",
            )
            return job_id

    async def list_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = await self._jobs.list_jobs(limit=limit)
        return [self._serialize_job(row) for row in rows]

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        row = await self._jobs.get_job(job_id)
        if not row:
            return None
        return self._serialize_job(row)

    async def _run_job(self, job_id: str, model_family: str, scan_limit: int) -> None:
        global _running_backfill_job_id
        try:
            await self._jobs.update_job(
                job_id,
                {
                    "status": "running",
                    "started_at": datetime.utcnow(),
                    "model_family": model_family,
                    "scan_limit": scan_limit,
                },
            )
            result = await self._backfill_family(model_family, scan_limit)
            await self._jobs.update_job(
                job_id,
                {
                    "status": "succeeded",
                    "finished_at": datetime.utcnow(),
                    "result": result,
                    "error": None,
                },
            )
        except Exception as exc:  # noqa: BLE001
            await self._jobs.update_job(
                job_id,
                {
                    "status": "failed",
                    "finished_at": datetime.utcnow(),
                    "error": str(exc)[:1000],
                },
            )
        finally:
            async with _backfill_lock:
                if _running_backfill_job_id == job_id:
                    _running_backfill_job_id = None

    async def _backfill_family(self, model_family: str, scan_limit: int) -> Dict[str, Any]:
        await self._ml.refresh_model_catalog(force=True)
        logs = await self._load_family_logs(model_family, scan_limit)

        processed = 0
        updated_logs = 0
        created_alerts = 0
        refreshed_alerts = 0
        suppressed_alerts = 0
        benign_results = 0
        attack_results = 0
        failures: List[Dict[str, str]] = []

        for log in logs:
            log_id = str(log.get("_id") or "")
            if not log_id:
                continue
            processed += 1
            try:
                feature_patch = self._feature_patch(log)
                result, model_version = await self._ml.infer_single_log(log)
                await self._logs.mark_ml_done(log["_id"], result, model_version)
                await self._logs.update_fields_by_id(log_id, feature_patch)
                updated_logs += 1

                existing_alert = await self._alerts.get_alert_by_log_id(log_id)
                if result["alert_type"] == "benign":
                    benign_results += 1
                    if existing_alert:
                        await self._alerts.update_alert_fields(
                            str(existing_alert["_id"]),
                            {
                                "status": "reclassified_benign",
                                "model_version": model_version,
                                "metadata.reclassification": {
                                    "family": model_family,
                                    "at": datetime.utcnow(),
                                    "new_alert_type": "benign",
                                    "new_classification": None,
                                },
                            },
                        )
                        suppressed_alerts += 1
                    continue

                attack_results += 1
                severity = "high" if result["alert_type"] == "known_attack" else "medium"
                metadata_patch = {
                    "source": log.get("source"),
                    "message": (log.get("message") or "")[:200],
                    "model_family": result.get("model_family"),
                    "feature_schema_version": result.get("feature_schema_version"),
                    "classification_source": result.get("classification_source", "model"),
                    "rules_reason": result.get("rules_reason"),
                    "reclassification": {
                        "family": model_family,
                        "at": datetime.utcnow(),
                        "new_alert_type": result["alert_type"],
                        "new_classification": result.get("classification"),
                    },
                }
                if existing_alert:
                    await self._alerts.update_alert_fields(
                        str(existing_alert["_id"]),
                        {
                            "status": "open",
                            "alert_type": result["alert_type"],
                            "severity": severity,
                            "classification": result.get("classification"),
                            "anomaly_score": float(result.get("score", 0.0)),
                            "model_version": model_version,
                            "metadata": metadata_patch,
                        },
                    )
                    refreshed_alerts += 1
                    continue

                await self._alert_service.create_or_get_alert(
                    log_id=log_id,
                    alert_type=result["alert_type"],
                    severity=severity,
                    model_version=model_version,
                    metadata=metadata_patch,
                    classification=result.get("classification"),
                    anomaly_score=float(result.get("score", 0.0)),
                )
                created_alerts += 1
            except Exception as exc:  # noqa: BLE001
                failures.append({"log_id": log_id, "error": str(exc)[:300]})

        return {
            "model_family": model_family,
            "scan_limit": scan_limit,
            "processed_logs": processed,
            "updated_logs": updated_logs,
            "benign_results": benign_results,
            "attack_results": attack_results,
            "created_alerts": created_alerts,
            "refreshed_alerts": refreshed_alerts,
            "suppressed_alerts": suppressed_alerts,
            "failed": len(failures),
            "errors": failures[:50],
        }

    async def _load_family_logs(self, model_family: str, limit: int) -> List[Dict[str, Any]]:
        decoders = [
            decoder
            for decoder, family in self._engineer.DECODER_TO_FAMILY.items()
            if family == model_family
        ]
        filters: Dict[str, Any] = {"metadata.raw_wazuh_payload": {"$exists": True}}
        if decoders:
            filters["metadata.raw_wazuh_payload.decoder.name"] = {"$in": decoders}
        return await self._logs.list_logs(limit=limit, offset=0, filters=filters)

    def _feature_patch(self, log: Dict[str, Any]) -> Dict[str, Any]:
        metadata = log.get("metadata") or {}
        payload = metadata.get("raw_wazuh_payload") if isinstance(metadata, dict) else None
        if not isinstance(payload, dict):
            return {}
        message = str(payload.get("full_log") or payload.get("rule", {}).get("description") or log.get("message") or "")
        engineered = self._engineer.engineer_payload(payload, message_override=message)
        return {
            "metadata.model_family": engineered.get("model_family"),
            "metadata.feature_schema_version": engineered.get("feature_schema_version"),
            "metadata.engineered_features": engineered.get("engineered_features", {}),
            "metadata.ml_routing_reason": engineered.get("routing_reason"),
        }

    def _normalize_model_family(self, model_family: str) -> str:
        normalized = str(model_family or "").strip().lower()
        if normalized not in self._engineer.SCHEMA_BY_FAMILY:
            supported = ", ".join(sorted(self._engineer.SCHEMA_BY_FAMILY))
            raise RuntimeError(f"Unsupported model family '{model_family}'. Supported families: {supported}")
        return normalized

    @staticmethod
    def _serialize_job(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(row.get("_id")),
            "status": row.get("status"),
            "reason": row.get("reason"),
            "requested_by": row.get("requested_by"),
            "model_family": row.get("model_family"),
            "scan_limit": row.get("scan_limit"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "result": row.get("result") or {},
            "error": row.get("error"),
        }
