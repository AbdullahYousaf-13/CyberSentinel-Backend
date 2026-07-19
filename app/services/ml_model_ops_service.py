import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.db.repositories.raw_wazuh_log_repository import RawWazuhLogRepository
from app.db.repositories.retrain_job_repository import RetrainJobRepository
from app.ml.training.wazuh_dataset_builder import CLASS_ORDER, WazuhDatasetBuilder

_job_lock = asyncio.Lock()
_running_job_id: Optional[str] = None
_INTERRUPTED_RETRAIN_ERROR = "Backend restarted before retrain completed"


class MLModelOpsService:
    _HISTORICAL_CANDIDATE_MULTIPLIER = 2
    _RECENT_CANDIDATE_MULTIPLIER = 5

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jobs = RetrainJobRepository()
        self._logs = LogRepository()
        self._raw_wazuh_logs = RawWazuhLogRepository()
        self._dataset_builder = WazuhDatasetBuilder()

    async def list_versions(self) -> List[Dict[str, Any]]:
        base_url = self._model_base_url()
        headers = self._admin_headers()
        async with httpx.AsyncClient(timeout=max(3, self._settings.model_api_timeout_seconds)) as client:
            response = await client.get(f"{base_url}/models/versions", headers=headers)
            response.raise_for_status()
            body = response.json()
        versions = body.get("versions")
        if not isinstance(versions, list):
            return []
        return versions

    async def rollback(self, target_version: str) -> Dict[str, Any]:
        base_url = self._model_base_url()
        headers = self._admin_headers()
        async with httpx.AsyncClient(timeout=max(3, self._settings.model_api_timeout_seconds)) as client:
            response = await client.post(
                f"{base_url}/models/activate",
                json={"version": target_version},
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    async def create_retrain_job(self, reason: str, requested_by: str) -> str:
        global _running_job_id
        async with _job_lock:
            if _running_job_id:
                raise RuntimeError("Another retrain job is already running")
            payload = {
                "status": "queued",
                "reason": reason.strip()[:300],
                "requested_by": requested_by,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "metrics": {},
                "error": None,
            }
            job_id = await self._jobs.create_job(payload)
            _running_job_id = job_id
            asyncio.create_task(self._run_job(job_id), name=f"ml-retrain-{job_id}")
            return job_id

    async def list_retrain_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = await self._jobs.list_jobs(limit=limit)
        return [self._serialize_job(row) for row in rows]

    async def get_retrain_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        row = await self._jobs.get_job(job_id)
        if not row:
            return None
        return self._serialize_job(row)

    async def _run_job(self, job_id: str) -> None:
        global _running_job_id
        try:
            await self._jobs.update_job(job_id, {"status": "running", "started_at": datetime.utcnow()})
            dataset = await self._build_dataset()
            self._validate_dataset(dataset)
            result = await self._train_remote(dataset)
            await self._jobs.update_job(
                job_id,
                {
                    "status": "succeeded",
                    "finished_at": datetime.utcnow(),
                    "result": result,
                    "metrics": result.get("metrics", {}),
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
            async with _job_lock:
                if _running_job_id == job_id:
                    _running_job_id = None

    async def _build_dataset(self) -> Dict[str, Any]:
        dataset = await self._build_bootstrap_dataset()
        feedback_sets = await self._fetch_feedback_sets()
        dataset = await self._augment_dataset_with_feedback(dataset, feedback_sets)
        return dataset

    async def recover_incomplete_jobs(self) -> int:
        global _running_job_id
        count = await self._jobs.fail_incomplete_jobs(_INTERRUPTED_RETRAIN_ERROR)
        async with _job_lock:
            _running_job_id = None
        return count

    async def _build_bootstrap_dataset(self) -> Dict[str, Any]:
        min_samples = max(1, int(self._settings.min_samples_per_attack_class))
        recent_limit = max(1, int(getattr(self._settings, "retrain_raw_wazuh_db_limit", 10000)))
        historical_target = max(1, int(getattr(self._settings, "retrain_historical_base_target", 25000)))
        candidate_limit = max(
            recent_limit * self._RECENT_CANDIDATE_MULTIPLIER,
            historical_target * self._HISTORICAL_CANDIDATE_MULTIPLIER,
            recent_limit + historical_target,
        )
        fallback_errors: List[str] = []

        rows = await self._raw_wazuh_logs.list_recent_for_retraining(candidate_limit)
        if rows:
            try:
                dataset = await asyncio.to_thread(
                    self._compose_balanced_dataset_from_rows,
                    rows,
                    min_samples,
                    recent_limit,
                    historical_target,
                )
                report = dataset.get("report") or {}
                report["source"] = "mongodb"
                report["source_collection"] = "raw_wazuh_logs"
                report["source_row_count"] = len(rows)
                report["source_limit"] = candidate_limit
                report["recent_slice_target"] = recent_limit
                report["historical_base_target"] = historical_target
                dataset["report"] = report
                return dataset
            except RuntimeError as exc:
                fallback_errors.append(f"Database raw_wazuh_logs dataset unavailable: {exc}")
        else:
            fallback_errors.append("No raw Wazuh logs available in database")

        fallback_path = str(getattr(self._settings, "raw_wazuh_training_path", "") or "").strip()
        if fallback_path:
            try:
                rows = self._dataset_builder.load_rows(fallback_path)
                dataset = self._compose_balanced_dataset_from_rows(
                    rows,
                    min_samples,
                    recent_limit,
                    historical_target,
                )
                report = dataset.get("report") or {}
                report["source"] = "file_fallback"
                report["source_path"] = fallback_path
                report["source_row_count"] = len(rows)
                report["recent_slice_target"] = recent_limit
                report["historical_base_target"] = historical_target
                dataset["report"] = report
                return dataset
            except RuntimeError as exc:
                fallback_errors.append(f"Fallback dataset file unavailable: {exc}")
        else:
            fallback_errors.append("RAW_WAZUH_TRAINING_PATH is not configured")

        raise RuntimeError(" | ".join(fallback_errors))

    async def _augment_dataset_with_feedback(self, dataset: Dict[str, Any], feedback_sets: Dict[str, Any]) -> Dict[str, Any]:
        feature_names = dataset.get("feature_names") or []
        if not feature_names:
            return dataset

        confirmed_known = feedback_sets["confirmed_known"]
        false_positive_ids = feedback_sets["false_positive_log_ids"]
        confirmed_logs = await self._logs.list_logs_by_ids([item["log_id"] for item in confirmed_known])
        false_positive_logs = await self._logs.list_logs_by_ids(list(false_positive_ids))

        return await asyncio.to_thread(
            self._augment_dataset_with_feedback_sync,
            dataset,
            feature_names,
            confirmed_known,
            confirmed_logs,
            false_positive_logs,
        )

    def _augment_dataset_with_feedback_sync(
        self,
        dataset: Dict[str, Any],
        feature_names: List[str],
        confirmed_known: List[Dict[str, Any]],
        confirmed_logs: List[Dict[str, Any]],
        false_positive_logs: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        features: List[List[float]] = dataset.get("features") or []
        labels: List[int] = dataset.get("labels") or []
        raw_ingest_keys: List[str | None] = list(dataset.get("_training_raw_ingest_keys") or [None for _ in features])
        label_map_raw: Dict[str, str] = dataset.get("label_map") or {}
        class_to_id = {v.lower(): int(k) for k, v in label_map_raw.items()}

        promoted_by_id = {item["log_id"]: item["classification"] for item in confirmed_known}
        for log in confirmed_logs:
            raw_ingest_key = self._log_raw_ingest_key(log)
            self._drop_existing_training_row(features, labels, raw_ingest_keys, raw_ingest_key)
            vec = self._vector_from_log(log, feature_names)
            cls = self._normalize_feedback_class(promoted_by_id.get(str(log.get("_id")), "other_attack"))
            label_id = class_to_id.get(cls, class_to_id.get("other_attack", class_to_id.get("benign", 0)))
            features.append(vec)
            labels.append(int(label_id))
            raw_ingest_keys.append(raw_ingest_key)

        benign_id = class_to_id.get("benign", 0)
        for log in false_positive_logs:
            raw_ingest_key = self._log_raw_ingest_key(log)
            self._drop_existing_training_row(features, labels, raw_ingest_keys, raw_ingest_key)
            vec = self._vector_from_log(log, feature_names)
            features.append(vec)
            labels.append(int(benign_id))
            raw_ingest_keys.append(raw_ingest_key)

        dataset["features"] = features
        dataset["labels"] = labels
        dataset["_training_raw_ingest_keys"] = raw_ingest_keys
        report = dataset.get("report") or {}
        report["feedback_augmented"] = {
            "confirmed_known_used": len(confirmed_logs),
            "false_positive_used": len(false_positive_logs),
        }
        report["final_total_samples"] = len(features)
        dataset["report"] = report
        return dataset

    async def _fetch_feedback_sets(self) -> Dict[str, Any]:
        rows = await self._logs.list_logs(limit=10000, offset=0, filters={"metadata.feedback.verdict": {"$exists": True}})
        confirmed_known: List[Dict[str, Any]] = []
        false_positive_log_ids: set[str] = set()
        for row in rows:
            metadata = row.get("metadata") or {}
            if not isinstance(metadata, dict):
                continue
            feedback = metadata.get("feedback")
            if not isinstance(feedback, dict):
                continue
            verdict = str(feedback.get("verdict") or "").strip().lower()
            if verdict == "false_positive":
                false_positive_log_ids.add(str(row.get("_id")))
                continue
            if verdict != "confirmed_known_attack":
                continue
            mp = metadata.get("manual_promotion")
            cls = ""
            if isinstance(mp, dict):
                cls = str(mp.get("classification") or "").strip()
            if not cls:
                cls = str((((row.get("ml_result") or {}).get("classification")) or "")).strip()
            if not cls:
                continue
            confirmed_known.append({"log_id": str(row.get("_id")), "classification": cls})
        return {
            "confirmed_known": confirmed_known,
            "false_positive_log_ids": false_positive_log_ids,
        }

    @staticmethod
    def _feature_names_from_logs(logs: List[Dict[str, Any]]) -> List[str]:
        for row in logs:
            metadata = row.get("metadata") or {}
            features = metadata.get("engineered_features_v1") or metadata.get("engineered_features_78")
            if isinstance(features, dict) and features:
                return list(features.keys())
        return []

    @staticmethod
    def _vector_from_log(log: Dict[str, Any], feature_names: List[str]) -> List[float]:
        metadata = (log.get("metadata") or {})
        features = metadata.get("engineered_features_v1") or metadata.get("engineered_features_78")
        if not isinstance(features, dict):
            return [0.0 for _ in feature_names]
        out: List[float] = []
        for name in feature_names:
            value = features.get(name, 0.0)
            try:
                out.append(float(value))
            except Exception:  # noqa: BLE001
                out.append(0.0)
        return out

    @staticmethod
    def _validate_dataset(dataset: Dict[str, Any]) -> None:
        features = dataset.get("features") or []
        labels = dataset.get("labels") or []
        if len(features) != len(labels):
            raise RuntimeError("Training dataset is invalid: features/labels length mismatch")
        if len(features) < 400:
            raise RuntimeError("Training dataset too small")
        if len(set(labels)) < 2:
            raise RuntimeError("Training dataset must contain at least benign and one attack class")

    @staticmethod
    def _normalize_feedback_class(raw: str) -> str:
        normalized = str(raw or "").strip().lower()
        normalized = normalized.replace("known_attack_", "")
        normalized = normalized.replace(" ", "_")
        if normalized in CLASS_ORDER:
            return normalized
        return "other_attack"

    def _compose_balanced_dataset_from_rows(
        self,
        rows: List[Dict[str, Any]],
        min_samples_per_class: int,
        recent_limit: int,
        historical_target: int,
    ) -> Dict[str, Any]:
        prepared_rows = self._dataset_builder.prepare_rows(rows)
        if len(prepared_rows) < 50:
            raise RuntimeError("No usable Wazuh events found in raw dataset")

        recent_count = min(recent_limit, len(prepared_rows))
        recent_rows = prepared_rows[-recent_count:]
        historical_candidates = prepared_rows[:-recent_count] if len(prepared_rows) > recent_count else []
        historical_base = self._select_historical_base(historical_candidates, historical_target)
        selected_rows = self._merge_prepared_rows(historical_base, recent_rows)

        report = {
            "selection_strategy": "balanced_historical_base_plus_recent_slice",
            "balancing_rule": "per_class_cap",
            "sampling_order": "mixed_spread",
            "historical_base_samples": len(historical_base),
            "recent_slice_samples": len(recent_rows),
            "final_pre_feedback_samples": len(selected_rows),
        }
        return self._dataset_builder.build_from_prepared_rows(
            selected_rows,
            min_samples_per_class=min_samples_per_class,
            report=report,
        )

    def _select_historical_base(self, rows: List[Dict[str, Any]], historical_target: int) -> List[Dict[str, Any]]:
        if not rows or historical_target <= 0:
            return []

        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(str(row.get("label") or "other_attack"), []).append(row)
        if not grouped:
            return []

        class_count = max(1, len(grouped))
        per_class_cap = max(1, historical_target // class_count)
        selected: List[Dict[str, Any]] = []
        selected_keys: set[str] = set()

        for items in grouped.values():
            sampled = self._sample_mixed_spread(items, per_class_cap)
            for row in sampled:
                key = str(row.get("dedup_key") or "")
                if key in selected_keys:
                    continue
                selected_keys.add(key)
                selected.append(row)

        return self._merge_prepared_rows([], selected)

    @staticmethod
    def _sample_mixed_spread(rows: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        if limit <= 0 or not rows:
            return []
        if len(rows) <= limit:
            return list(rows)
        if limit == 1:
            return [rows[len(rows) // 2]]

        last_index = len(rows) - 1
        indices = sorted({round((last_index * idx) / (limit - 1)) for idx in range(limit)})
        if len(indices) < limit:
            used = set(indices)
            for idx in range(len(rows)):
                if idx in used:
                    continue
                indices.append(idx)
                used.add(idx)
                if len(indices) == limit:
                    break
            indices.sort()
        return [rows[idx] for idx in indices[:limit]]

    @staticmethod
    def _merge_prepared_rows(primary: List[Dict[str, Any]], secondary: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        for row in primary + secondary:
            key = str(row.get("dedup_key") or "")
            if key not in merged:
                order.append(key)
            merged[key] = row
        ordered_rows = [merged[key] for key in order if key in merged]
        return sorted(ordered_rows, key=MLModelOpsService._prepared_sort_key)

    @staticmethod
    def _prepared_sort_key(row: Dict[str, Any]) -> tuple[str, str]:
        timestamp = row.get("timestamp")
        timestamp_text = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp or "")
        return (timestamp_text, str(row.get("dedup_key") or ""))

    @staticmethod
    def _log_raw_ingest_key(log: Dict[str, Any]) -> str | None:
        metadata = log.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        value = metadata.get("raw_ingest_key")
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    @staticmethod
    def _drop_existing_training_row(
        features: List[List[float]],
        labels: List[int],
        raw_ingest_keys: List[str | None],
        raw_ingest_key: str | None,
    ) -> None:
        if not raw_ingest_key:
            return
        for idx in range(len(raw_ingest_keys) - 1, -1, -1):
            if raw_ingest_keys[idx] != raw_ingest_key:
                continue
            del raw_ingest_keys[idx]
            del features[idx]
            del labels[idx]

    async def _train_remote(self, dataset: Dict[str, Any]) -> Dict[str, Any]:
        base_url = self._model_base_url()
        headers = self._admin_headers()
        payload = {key: value for key, value in dataset.items() if not str(key).startswith("_")}
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(f"{base_url}/train", json=payload, headers=headers)
            response.raise_for_status()
            body = response.json()
            job_id = str(body.get("id") or "").strip()
            if not job_id:
                return body

            for _ in range(240):
                job_resp = await client.get(f"{base_url}/train/{job_id}", headers=headers)
                job_resp.raise_for_status()
                job = job_resp.json()
                status = str(job.get("status") or "").lower()
                if status in {"succeeded", "failed"}:
                    if status == "failed":
                        raise RuntimeError(str(job.get("error") or "Cloud retrain job failed"))
                    result = job.get("result")
                    if isinstance(result, dict):
                        return result
                    return {}
                await asyncio.sleep(1)
            raise RuntimeError("Cloud retrain job timed out")

    def _admin_headers(self) -> Dict[str, str]:
        token = (self._settings.model_admin_token or "").strip()
        if not token:
            raise RuntimeError("MODEL_ADMIN_TOKEN is required for model ops")
        return {"x-model-admin-token": token}

    def _model_base_url(self) -> str:
        model_api_url = (self._settings.model_api_url or "").strip().rstrip("/")
        if not model_api_url:
            raise RuntimeError("MODEL_API_URL is required")
        return model_api_url

    @staticmethod
    def _serialize_job(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(row.get("_id")),
            "status": row.get("status"),
            "reason": row.get("reason"),
            "requested_by": row.get("requested_by"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "metrics": row.get("metrics") or {},
            "result": row.get("result") or {},
            "error": row.get("error"),
        }
