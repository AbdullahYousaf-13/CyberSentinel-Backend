from datetime import datetime
from typing import Any, Dict
from app.db.repositories.log_repository import LogRepository


class IngestionService:
    def __init__(self) -> None:
        self._logs = LogRepository()

    async def ingest_log(self, payload: Dict[str, Any], source: str) -> str:
        # Normalize payload so all ingestion paths share the same storage contract.
        normalized = {
            "timestamp": payload.get("timestamp", datetime.utcnow()),
            "source": source,
            "message": payload.get("message", ""),
            "metadata": payload.get("metadata", {}),
            "severity": payload.get("severity"),
            "ingested_at": datetime.utcnow(),
        }
        return await self._logs.create_log(normalized)
