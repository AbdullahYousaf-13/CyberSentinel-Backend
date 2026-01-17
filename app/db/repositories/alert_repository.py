from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.db.mongo import get_db


class AlertRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("alerts")

    async def create_alert(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def list_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        cursor = self._collection.find().sort("created_at", -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(alert_id)})
