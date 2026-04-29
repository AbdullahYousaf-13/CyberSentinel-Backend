import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.db.repositories.retrain_job_repository import RetrainJobRepository

_job_lock = asyncio.Lock()
_running_job_id: Optional[str] = None


class MLModelOpsService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jobs = RetrainJobRepository()
        self._logs = LogRepository()

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
        feedback_sets = await self._fetch_feedback_sets()
        confirmed_known = feedback_sets["confirmed_known"]
        false_positive_ids = feedback_sets["false_positive_log_ids"]
        confirmed_feedback_count = len(confirmed_known) + len(false_positive_ids)
        if confirmed_feedback_count < 200:
            raise RuntimeError("At least 200 confirmed feedback events are required before retraining")

        confirmed_logs = await self._logs.list_logs_by_ids([item["log_id"] for item in confirmed_known])
        false_positive_logs = await self._logs.list_logs_by_ids(list(false_positive_ids))
        benign_logs = await self._logs.list_web_benign_logs(
            limit=max(200, len(confirmed_logs) + len(false_positive_logs))
        )

        feature_names = self._feature_names_from_logs(confirmed_logs or false_positive_logs or benign_logs)
        if not feature_names:
            raise RuntimeError("No engineered feature schema found in logs")

        label_to_id: Dict[str, int] = {"BENIGN": 0}
        features: List[List[float]] = []
        labels: List[int] = []

        promoted_by_id = {item["log_id"]: item["classification"] for item in confirmed_known}
        for log in confirmed_logs:
            log_id = str(log.get("_id"))
            cls = promoted_by_id.get(log_id)
            if not cls:
                continue
            label_to_id.setdefault(cls, len(label_to_id))
            vec = self._vector_from_log(log, feature_names)
            features.append(vec)
            labels.append(label_to_id[cls])

        # False-positive confirmed samples are explicitly safe to learn as benign.
        for log in false_positive_logs:
            vec = self._vector_from_log(log, feature_names)
            features.append(vec)
            labels.append(0)

        suppressed_ids = {str(item.get("_id")) for item in false_positive_logs}
        for log in benign_logs:
            if str(log.get("_id")) in suppressed_ids:
                continue
            vec = self._vector_from_log(log, feature_names)
            features.append(vec)
            labels.append(0)

        return {
            "reason": "manual_ops_retrain",
            "features": features,
            "labels": labels,
            "feature_names": feature_names,
            "label_map": {str(v): k for k, v in label_to_id.items()},
        }

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
            features = (row.get("metadata") or {}).get("engineered_features_78")
            if isinstance(features, dict) and features:
                return list(features.keys())
        return []

    @staticmethod
    def _vector_from_log(log: Dict[str, Any], feature_names: List[str]) -> List[float]:
        features = (log.get("metadata") or {}).get("engineered_features_78")
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

    async def _train_remote(self, dataset: Dict[str, Any]) -> Dict[str, Any]:
        base_url = self._model_base_url()
        headers = self._admin_headers()
        async with httpx.AsyncClient(timeout=180) as client:
            response = await client.post(f"{base_url}/train", json=dataset, headers=headers)
            response.raise_for_status()
            return response.json()

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
