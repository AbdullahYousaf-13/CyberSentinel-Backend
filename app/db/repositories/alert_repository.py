from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.db.mongo import get_db


class AlertRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("alerts")

    async def create_alert(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        query = filters or {}
        cursor = (
            self._collection.find(query)
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(alert_id)})
