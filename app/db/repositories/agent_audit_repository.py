from datetime import datetime
from typing import Any, Dict

from app.db.mongo import get_db


class AgentAuditRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("agent_audit")

    async def record_event(self, payload: Dict[str, Any]) -> str:
        payload["timestamp"] = datetime.utcnow()
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)
