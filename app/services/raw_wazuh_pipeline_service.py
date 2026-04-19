import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository
from app.db.repositories.raw_wazuh_log_repository import RawWazuhLogRepository
from app.ml.features.feature_extractor import FeatureExtractor
from app.services.alert_service import AlertService
from app.services.ml_service import MLService

logger = logging.getLogger(__name__)

_RETRY_BASE_SEC = 5
_RETRY_CAP_SEC = 60 * 60
_IDLE_SLEEP_SEC = 2.0
_BUSY_SLEEP_SEC = 0.25

_worker_task: Optional[asyncio.Task] = None
_worker_stop_event: Optional[asyncio.Event] = None


class RawWazuhPipelineService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._raw_repo = RawWazuhLogRepository()
        self._logs = LogRepository()
        self._alerts = AlertService()
        self._ml = MLService(settings)
        self._extractor = FeatureExtractor()

    async def ingest_batch(self, logs: List[Any], sent_at_ms: int) -> Dict[str, int]:
        incoming_count = len(logs)
        prepared = self.prepare_logs_for_ingest(logs)
        if not prepared:
            return {"inserted": 0, "duplicates": incoming_count, "scheduled": 0}

        result = await self._raw_repo.upsert_batch(prepared, sent_at_ms)
        inserted = int(result["inserted"])
        duplicates = int(result["duplicates"]) + max(incoming_count - len(prepared), 0)
        return {"inserted": inserted, "duplicates": duplicates, "scheduled": inserted}

    async def process_next_due(self) -> bool:
        claimed = await self._raw_repo.claim_next_for_processing()
        if not claimed:
            return False

        ingest_key = str(claimed.get("ingest_key") or "")
        if not ingest_key:
            return False

        try:
            await self._process_claimed(claimed)
            return True
        except Exception as exc:  # noqa: BLE001
            attempts = int(((claimed.get("processing") or {}).get("attempts") or 1))
            retry_delay = min(_RETRY_BASE_SEC * (2 ** max(attempts - 1, 0)), _RETRY_CAP_SEC)
            next_retry_at = datetime.utcnow() + timedelta(seconds=retry_delay)
            await self._raw_repo.mark_error(ingest_key, next_retry_at, str(exc))
            logger.exception("Failed processing raw Wazuh log %s", ingest_key)
            return True

    @staticmethod
    def prepare_logs_for_ingest(logs: List[Any]) -> List[Dict[str, Any]]:
        prepared: Dict[str, Dict[str, Any]] = {}
        for index, item in enumerate(logs):
            payload, ingest_meta = RawWazuhPipelineService._extract_payload_and_meta(item, index)
            ingest_key = RawWazuhPipelineService._build_ingest_key(payload, ingest_meta, index)
            if ingest_key in prepared:
                continue
            prepared[ingest_key] = {
                "ingest_key": ingest_key,
                "payload": payload,
                "ingest_meta": ingest_meta,
            }
        return list(prepared.values())

    @staticmethod
    def _extract_payload_and_meta(item: Any, index: int) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        if isinstance(item, dict) and isinstance(item.get("payload"), dict):
            payload = dict(item["payload"])
            ingest_meta = RawWazuhPipelineService._parse_ingest_meta(item.get("ingestMeta"))
            if ingest_meta:
                return payload, ingest_meta
            return payload, {"mode": "legacy", "batch_index": index}

        if isinstance(item, dict):
            return dict(item), {"mode": "legacy", "batch_index": index}
        return {"value": item}, {"mode": "legacy", "batch_index": index}

    @staticmethod
    def _parse_ingest_meta(raw_meta: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(raw_meta, dict):
            return None
        archive_path = raw_meta.get("archivePath")
        byte_offset = raw_meta.get("byteOffset")
        line_hash = raw_meta.get("lineHash")
        if not isinstance(archive_path, str) or not archive_path.strip():
            return None
        if not isinstance(byte_offset, int) or byte_offset < 0:
            return None
        if not isinstance(line_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", line_hash):
            return None
        return {
            "mode": "offset",
            "archive_path": archive_path.strip(),
            "byte_offset": byte_offset,
            "line_hash": line_hash.lower(),
        }

    @staticmethod
    def _build_ingest_key(payload: Dict[str, Any], ingest_meta: Dict[str, Any], index: int) -> str:
        if ingest_meta.get("mode") == "offset":
            raw = f"{ingest_meta['archive_path']}:{ingest_meta['byte_offset']}:{ingest_meta['line_hash']}"
            return hashlib.sha256(raw.encode("utf-8")).hexdigest()

        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        payload_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        raw = f"legacy:{payload_hash}:{index}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    async def _process_claimed(self, raw_doc: Dict[str, Any]) -> None:
        ingest_key = str(raw_doc["ingest_key"])
        payload = raw_doc.get("payload") or {}
        engineered_log = self._engineer_log(payload, ingest_key)
        stored = await self._logs.upsert_engineered_log(ingest_key, engineered_log)
        log_id_obj = stored["_id"]
        log_id = str(log_id_obj)

        if stored.get("ml_status") == "done":
            await self._raw_repo.mark_done(ingest_key, log_id)
            return

        try:
            result, model_version = await self._ml.infer_single_log(stored)
            await self._logs.mark_ml_done(log_id_obj, result, model_version)
        except Exception as exc:
            await self._logs.mark_ml_error(log_id_obj, str(exc))
            raise

        if result["alert_type"] != "benign":
            severity = "high" if result["alert_type"] == "known_attack" else "medium"
            await self._alerts.create_or_get_alert(
                log_id=log_id,
                alert_type=result["alert_type"],
                severity=severity,
                model_version=model_version,
                metadata={"source": stored.get("source"), "message": (stored.get("message") or "")[:200]},
                classification=result.get("classification"),
                anomaly_score=float(result.get("score", 0.0)),
            )

        await self._raw_repo.mark_done(ingest_key, log_id)

    def _engineer_log(self, payload: Dict[str, Any], ingest_key: str) -> Dict[str, Any]:
        rule = payload.get("rule", {}) if isinstance(payload.get("rule"), dict) else {}
        agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
        decoder = payload.get("decoder", {}) if isinstance(payload.get("decoder"), dict) else {}

        level = int(rule.get("level", 0) or 0)
        severity = "high" if level >= 12 else "medium" if level >= 7 else "low"
        message = str(rule.get("description") or payload.get("full_log") or decoder.get("name") or "wazuh alert")
        timestamp = self._parse_timestamp(payload.get("timestamp"))
        source = str(agent.get("name") or "wazuh")

        flattened = self._flatten_payload(payload)
        flattened["severity"] = severity
        features_vector = self._extractor.transform([{"metadata": flattened}])[0]
        engineered_features = {
            feature_name: float(features_vector[idx])
            for idx, feature_name in enumerate(self._extractor.CICIDS_2017_FEATURES)
        }

        metadata: Dict[str, Any] = {
            "raw_ingest_key": ingest_key,
            "raw_wazuh_payload": payload,
            "engineered_features_78": engineered_features,
        }
        metadata.update(engineered_features)

        return {
            "timestamp": timestamp,
            "source": source,
            "message": message,
            "severity": severity,
            "metadata": metadata,
            "ingested_at": datetime.utcnow(),
            "ml_status": "pending",
        }

    @staticmethod
    def _flatten_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        flattened: Dict[str, Any] = {}

        def _visit(prefix: str, value: Any) -> None:
            if isinstance(value, dict):
                for key, inner in value.items():
                    next_prefix = f"{prefix}_{key}" if prefix else str(key)
                    _visit(next_prefix, inner)
                return
            if isinstance(value, list):
                for idx, inner in enumerate(value):
                    next_prefix = f"{prefix}_{idx}" if prefix else str(idx)
                    _visit(next_prefix, inner)
                return
            if prefix:
                flattened[prefix] = value

        _visit("", payload)
        return flattened

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value
            return value.astimezone(timezone.utc).replace(tzinfo=None)

        if isinstance(value, (int, float)):
            ts = float(value)
            if ts > 10_000_000_000:
                ts = ts / 1000.0
            return datetime.utcfromtimestamp(ts)

        if isinstance(value, str):
            raw = value.strip()
            if raw:
                iso = raw.replace("Z", "+00:00")
                if re.search(r"[+-]\d{4}$", iso):
                    iso = f"{iso[:-5]}{iso[-5:-2]}:{iso[-2:]}"
                try:
                    parsed = datetime.fromisoformat(iso)
                    if parsed.tzinfo is None:
                        return parsed
                    return parsed.astimezone(timezone.utc).replace(tzinfo=None)
                except ValueError:
                    pass
        return datetime.utcnow()


async def start_raw_wazuh_background_worker(settings: Settings) -> None:
    global _worker_task, _worker_stop_event
    if _worker_task and not _worker_task.done():
        return

    _worker_stop_event = asyncio.Event()
    service = RawWazuhPipelineService(settings)

    async def _runner() -> None:
        assert _worker_stop_event is not None
        while not _worker_stop_event.is_set():
            try:
                processed = await service.process_next_due()
            except Exception:  # noqa: BLE001
                logger.exception("Raw Wazuh worker loop failure")
                processed = False
            await asyncio.sleep(_BUSY_SLEEP_SEC if processed else _IDLE_SLEEP_SEC)

    _worker_task = asyncio.create_task(_runner(), name="raw-wazuh-processor")
    logger.info("Raw Wazuh background worker started")


async def stop_raw_wazuh_background_worker() -> None:
    global _worker_task, _worker_stop_event
    if _worker_stop_event:
        _worker_stop_event.set()
    if _worker_task:
        try:
            await asyncio.wait_for(_worker_task, timeout=5.0)
        except asyncio.TimeoutError:
            _worker_task.cancel()
            try:
                await _worker_task
            except asyncio.CancelledError:
                pass
    _worker_task = None
    _worker_stop_event = None
