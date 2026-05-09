import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.ml.bootstrap import WazuhBootstrapDatasetBuilder
from app.db.repositories.retrain_job_repository import RetrainJobRepository
from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.wazuh_bootstrap_service import WazuhBootstrapService

_job_lock = asyncio.Lock()
_running_job_id: Optional[str] = None


class MLModelOpsService:
    MIN_ATTACK_SAMPLES = 200
    MIN_BENIGN_SAMPLES = 1000
    MIN_BINARY_BOOTSTRAP_BENIGN_SAMPLES = 400
    MIN_BINARY_BOOTSTRAP_TOTAL_SAMPLES = 1200
    DATASET_MODE_FEEDBACK_ONLY = "feedback_only"
    DATASET_MODE_BOOTSTRAP_SEED = "bootstrap_seed"
    DATASET_MODE_BOOTSTRAP_PLUS_FEEDBACK = "bootstrap_plus_feedback"
    VALID_DATASET_MODES = {
        DATASET_MODE_FEEDBACK_ONLY,
        DATASET_MODE_BOOTSTRAP_SEED,
        DATASET_MODE_BOOTSTRAP_PLUS_FEEDBACK,
    }

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._jobs = RetrainJobRepository()
        self._logs = LogRepository()
        self._engineer = WazuhFamilyFeatureEngineer()
        self._bootstrap = WazuhBootstrapService()

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

    async def create_retrain_job(
        self,
        reason: str,
        requested_by: str,
        model_family: str = "web_access",
        dataset_mode: str = DATASET_MODE_FEEDBACK_ONLY,
    ) -> str:
        global _running_job_id
        async with _job_lock:
            if _running_job_id:
                raise RuntimeError("Another retrain job is already running")
            normalized_family = self._normalize_model_family(model_family)
            normalized_dataset_mode = self._normalize_dataset_mode(dataset_mode)
            payload = {
                "status": "queued",
                "reason": reason.strip()[:300],
                "requested_by": requested_by,
                "model_family": normalized_family,
                "dataset_mode": normalized_dataset_mode,
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "metrics": {},
                "result": {},
                "error": None,
            }
            job_id = await self._jobs.create_job(payload)
            _running_job_id = job_id
            asyncio.create_task(
                self._run_job(job_id, normalized_family, normalized_dataset_mode),
                name=f"ml-retrain-{job_id}",
            )
            return job_id

    async def list_retrain_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = await self._jobs.list_jobs(limit=limit)
        return [self._serialize_job(row) for row in rows]

    async def get_retrain_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        row = await self._jobs.get_job(job_id)
        if not row:
            return None
        return self._serialize_job(row)

    async def _run_job(self, job_id: str, model_family: str, dataset_mode: str) -> None:
        global _running_job_id
        try:
            await self._jobs.update_job(
                job_id,
                {
                    "status": "running",
                    "started_at": datetime.utcnow(),
                    "model_family": model_family,
                    "dataset_mode": dataset_mode,
                },
            )
            dataset = await self._build_dataset(model_family, dataset_mode)
            prepared_dataset = self._prepare_dataset_for_training(dataset, dataset_mode)
            result = await self._train_remote(prepared_dataset)
            result.setdefault("dataset_summary", dataset.get("dataset_summary", {}))
            result["dataset_summary"] = prepared_dataset.get("dataset_summary", {})
            result["training_strategy"] = prepared_dataset.get("dataset_summary", {}).get("training_strategy")
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

    async def _build_dataset(self, model_family: str, dataset_mode: str) -> Dict[str, Any]:
        if dataset_mode == self.DATASET_MODE_BOOTSTRAP_SEED:
            return await self._build_bootstrap_dataset(model_family, include_feedback_overrides=False)
        if dataset_mode == self.DATASET_MODE_BOOTSTRAP_PLUS_FEEDBACK:
            return await self._build_bootstrap_dataset(model_family, include_feedback_overrides=True)
        return await self._build_feedback_dataset(model_family)

    async def _build_bootstrap_dataset(self, model_family: str, include_feedback_overrides: bool) -> Dict[str, Any]:
        dataset = await self._bootstrap.build_training_payload(
            model_family,
            scan_limit=5000,
            min_class_support=10,
            include_feedback_overrides=include_feedback_overrides,
        )
        return dataset

    async def _build_feedback_dataset(self, model_family: str) -> Dict[str, Any]:
        normalized_family = self._normalize_model_family(model_family)
        feedback_sets = await self._fetch_feedback_sets(normalized_family)
        confirmed_known = feedback_sets["confirmed_known"]
        benign_feedback_ids = feedback_sets["benign_feedback_log_ids"]

        confirmed_logs = await self._logs.list_logs_by_ids([item["log_id"] for item in confirmed_known])
        false_positive_logs = await self._logs.list_logs_by_ids(list(benign_feedback_ids))
        benign_logs = await self._logs.list_family_benign_logs(
            normalized_family,
            limit=max(self.MIN_BENIGN_SAMPLES * 2, len(false_positive_logs) + len(confirmed_logs) * 4),
        )

        schema_version = self._schema_version_from_logs(confirmed_logs or false_positive_logs or benign_logs, normalized_family)
        if not schema_version:
            raise RuntimeError(f"No engineered feature schema found for model family {normalized_family}")

        label_to_id: Dict[str, int] = {"BENIGN": 0}
        rows: List[Tuple[str, Dict[str, Any], int, str]] = []
        seen_keys: set[str] = set()

        promoted_by_id = {item["log_id"]: item["classification"] for item in confirmed_known}
        for log in confirmed_logs:
            log_id = str(log.get("_id"))
            cls = promoted_by_id.get(log_id)
            if not cls:
                continue
            label_to_id.setdefault(cls, len(label_to_id))
            self._append_dataset_row(rows, seen_keys, log, schema_version, label_to_id[cls])

        for log in false_positive_logs:
            self._append_dataset_row(rows, seen_keys, log, schema_version, 0)

        for log in benign_logs:
            self._append_dataset_row(rows, seen_keys, log, schema_version, 0)

        rows.sort(key=lambda item: item[0])
        samples = [sample for _, sample, _, _ in rows]
        labels = [label for _, _, label, _ in rows]
        timestamps = [timestamp for _, _, _, timestamp in rows]

        return {
            "reason": "manual_ops_retrain",
            "model_family": normalized_family,
            "feature_schema_version": schema_version,
            "samples": samples,
            "labels": labels,
            "timestamps": timestamps,
            "label_map": {str(v): k for k, v in label_to_id.items()},
            "dataset_summary": {
                "label_distribution": {
                    "BENIGN": labels.count(0),
                    "ATTACK": sum(1 for label in labels if int(label) != 0),
                }
            },
        }

    async def _fetch_feedback_sets(self, model_family: str) -> Dict[str, Any]:
        rows = await self._logs.list_logs(
            limit=20000,
            offset=0,
            filters={
                "metadata.feedback.verdict": {"$exists": True},
                "metadata.model_family": model_family,
            },
        )
        confirmed_known: List[Dict[str, Any]] = []
        benign_feedback_log_ids: set[str] = set()
        for row in rows:
            metadata = row.get("metadata") or {}
            if not isinstance(metadata, dict):
                continue
            feedback = metadata.get("feedback")
            if not isinstance(feedback, dict):
                continue
            verdict = str(feedback.get("verdict") or "").strip().lower()
            if verdict in {"false_positive", "confirmed_benign"}:
                benign_feedback_log_ids.add(str(row.get("_id")))
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
            "benign_feedback_log_ids": benign_feedback_log_ids,
        }

    def _append_dataset_row(
        self,
        rows: List[Tuple[str, Dict[str, Any], int, str]],
        seen_keys: set[str],
        log: Dict[str, Any],
        schema_version: str,
        label: int,
    ) -> None:
        sample = self._sample_from_log(log, schema_version)
        if sample is None:
            return
        dedupe_key = self._dedupe_key(log)
        if dedupe_key in seen_keys:
            return
        seen_keys.add(dedupe_key)
        timestamp_sort_key, timestamp_value = self._timestamp_values(log)
        rows.append((timestamp_sort_key, sample, label, timestamp_value))

    @staticmethod
    def _dedupe_key(log: Dict[str, Any]) -> str:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict):
            ingest_key = metadata.get("raw_ingest_key")
            if isinstance(ingest_key, str) and ingest_key.strip():
                return ingest_key.strip()
        return str(log.get("_id"))

    @staticmethod
    def _timestamp_values(log: Dict[str, Any]) -> Tuple[str, str]:
        timestamp = log.get("timestamp")
        if isinstance(timestamp, datetime):
            iso = timestamp.isoformat()
            return iso, iso
        text = str(timestamp or "")
        return text, text

    def _schema_version_from_logs(self, logs: List[Dict[str, Any]], model_family: str) -> str:
        expected_schema = self._engineer.schema_for_family(model_family)
        if not expected_schema:
            raise RuntimeError(f"Unsupported model family {model_family}")
        for row in logs:
            metadata = row.get("metadata") or {}
            if not isinstance(metadata, dict):
                continue
            schema = metadata.get("feature_schema_version")
            features = metadata.get("engineered_features")
            if schema == expected_schema and isinstance(features, dict) and isinstance(features.get(schema), dict):
                return schema
        return expected_schema

    @staticmethod
    def _sample_from_log(log: Dict[str, Any], schema_version: str) -> Optional[Dict[str, Any]]:
        metadata = log.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        features = metadata.get("engineered_features")
        if not isinstance(features, dict):
            return None
        sample = features.get(schema_version)
        if not isinstance(sample, dict):
            return None
        return sample

    @classmethod
    def _prepare_dataset_for_training(cls, dataset: Dict[str, Any], dataset_mode: str) -> Dict[str, Any]:
        samples = dataset.get("samples") or []
        labels = dataset.get("labels") or []
        if len(samples) != len(labels):
            raise RuntimeError("Training dataset is invalid: samples/labels length mismatch")

        benign = sum(1 for label in labels if int(label) == 0)
        attacks = sum(1 for label in labels if int(label) != 0)
        unique_labels = {int(label) for label in labels}

        if len(unique_labels) < 2:
            raise RuntimeError("Training dataset must contain benign and at least one attack class")
        if len(samples) < cls.MIN_BENIGN_SAMPLES + cls.MIN_ATTACK_SAMPLES:
            if cls._can_use_binary_bootstrap(dataset, dataset_mode, benign, attacks):
                return cls._collapse_dataset_to_binary_bootstrap(dataset)
            raise RuntimeError("Training dataset is too small for family retraining")
        if benign < cls.MIN_BENIGN_SAMPLES:
            if cls._can_use_binary_bootstrap(dataset, dataset_mode, benign, attacks):
                return cls._collapse_dataset_to_binary_bootstrap(dataset)
            raise RuntimeError(f"At least {cls.MIN_BENIGN_SAMPLES} benign samples are required before retraining")
        if attacks < cls.MIN_ATTACK_SAMPLES:
            raise RuntimeError(f"At least {cls.MIN_ATTACK_SAMPLES} attack-labeled samples are required before retraining")
        summary = dict(dataset.get("dataset_summary") or {})
        summary.setdefault("training_strategy", "family_multiclass")
        summary.setdefault(
            "effective_label_distribution",
            cls._label_distribution(dataset.get("labels") or [], dataset.get("label_map") or {}),
        )
        dataset["dataset_summary"] = summary
        dataset["training_strategy"] = str(summary.get("training_strategy") or "family_multiclass")
        return dataset

    @classmethod
    def _can_use_binary_bootstrap(
        cls,
        dataset: Dict[str, Any],
        dataset_mode: str,
        benign: int,
        attacks: int,
    ) -> bool:
        if dataset_mode not in {
            cls.DATASET_MODE_BOOTSTRAP_SEED,
            cls.DATASET_MODE_BOOTSTRAP_PLUS_FEEDBACK,
        }:
            return False
        total = len(dataset.get("labels") or [])
        if total < cls.MIN_BINARY_BOOTSTRAP_TOTAL_SAMPLES:
            return False
        if benign < cls.MIN_BINARY_BOOTSTRAP_BENIGN_SAMPLES:
            return False
        if attacks < cls.MIN_ATTACK_SAMPLES:
            return False
        return True

    @classmethod
    def _collapse_dataset_to_binary_bootstrap(cls, dataset: Dict[str, Any]) -> Dict[str, Any]:
        model_family = str(dataset.get("model_family") or "").strip().lower()
        generic_attack_label = WazuhBootstrapDatasetBuilder.GENERIC_ATTACK_LABEL_BY_FAMILY.get(
            model_family,
            "GENERIC_ATTACK",
        )
        binary_labels = [0 if int(label) == 0 else 1 for label in (dataset.get("labels") or [])]
        binary_dataset = dict(dataset)
        binary_dataset["labels"] = binary_labels
        binary_dataset["label_map"] = {"0": "BENIGN", "1": generic_attack_label}

        summary = dict(dataset.get("dataset_summary") or {})
        summary["training_strategy"] = "family_binary_bootstrap"
        summary["original_label_distribution"] = cls._label_distribution(
            dataset.get("labels") or [],
            dataset.get("label_map") or {},
        )
        summary["effective_label_distribution"] = cls._label_distribution(binary_labels, binary_dataset["label_map"])
        summary["binary_bootstrap_thresholds"] = {
            "min_total_samples": cls.MIN_BINARY_BOOTSTRAP_TOTAL_SAMPLES,
            "min_benign_samples": cls.MIN_BINARY_BOOTSTRAP_BENIGN_SAMPLES,
            "min_attack_samples": cls.MIN_ATTACK_SAMPLES,
        }
        binary_dataset["dataset_summary"] = summary
        binary_dataset["training_strategy"] = "family_binary_bootstrap"
        return binary_dataset

    @staticmethod
    def _label_distribution(labels: List[int], label_map: Dict[str, str]) -> Dict[str, int]:
        distribution: Dict[str, int] = {}
        for label in labels:
            normalized = int(label)
            label_name = str(label_map.get(str(normalized), normalized))
            distribution[label_name] = distribution.get(label_name, 0) + 1
        return distribution

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

    def _normalize_model_family(self, model_family: str) -> str:
        normalized = str(model_family or "").strip().lower()
        if normalized not in self._engineer.SCHEMA_BY_FAMILY:
            supported = ", ".join(sorted(self._engineer.SCHEMA_BY_FAMILY))
            raise RuntimeError(f"Unsupported model family '{model_family}'. Supported families: {supported}")
        return normalized

    def _normalize_dataset_mode(self, dataset_mode: str) -> str:
        normalized = str(dataset_mode or "").strip().lower()
        if normalized not in self.VALID_DATASET_MODES:
            supported = ", ".join(sorted(self.VALID_DATASET_MODES))
            raise RuntimeError(f"Unsupported dataset mode '{dataset_mode}'. Supported modes: {supported}")
        return normalized

    @staticmethod
    def _serialize_job(row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(row.get("_id")),
            "status": row.get("status"),
            "reason": row.get("reason"),
            "requested_by": row.get("requested_by"),
            "model_family": row.get("model_family"),
            "dataset_mode": row.get("dataset_mode"),
            "created_at": row.get("created_at"),
            "updated_at": row.get("updated_at"),
            "started_at": row.get("started_at"),
            "finished_at": row.get("finished_at"),
            "metrics": row.get("metrics") or {},
            "result": row.get("result") or {},
            "error": row.get("error"),
        }
