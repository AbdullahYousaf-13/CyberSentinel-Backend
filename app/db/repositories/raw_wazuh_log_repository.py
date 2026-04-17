from datetime import datetime
from typing import Any, Dict, List

from app.db.mongo import get_db


class RawWazuhLogRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("raw_wazuh_logs")

    async def insert_batch(self, logs: List[Dict[str, Any]]) -> int:
        if not logs:
            return 0
        now = datetime.utcnow()
        docs = [{"payload": entry, "ingested_at": now} for entry in logs]
        result = await self._collection.insert_many(docs)
        return len(result.inserted_ids)
