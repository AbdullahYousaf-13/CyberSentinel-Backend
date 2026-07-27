from typing import Any, Dict
from app.db.repositories.log_repository import LogRepository
from app.utils.time import coerce_datetime_utc, utc_now_naive


class IngestionService:
    def __init__(self) -> None:
        self._logs = LogRepository()

    async def ingest_log(self, payload: Dict[str, Any], source: str) -> str:
        # Normalize payload so all ingestion paths share the same storage contract.
        now = utc_now_naive()
        normalized = {
            "timestamp": coerce_datetime_utc(payload.get("timestamp"), fallback=now),
            "source": source,
            "message": payload.get("message", ""),
            "metadata": payload.get("metadata", {}),
            "severity": payload.get("severity"),
            "ingested_at": now,
            "ml_status": "pending",
        }
        return await self._logs.create_log(normalized)
