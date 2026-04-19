from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.db.mongo import get_db


class AlertRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("alerts")

    async def create_alert(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def create_or_get_alert(self, payload: Dict[str, Any]) -> tuple[str, bool]:
        query = {"log_id": payload["log_id"]}
        result = await self._collection.update_one(query, {"$setOnInsert": payload}, upsert=True)
        if result.upserted_id is not None:
            return str(result.upserted_id), True
        existing = await self._collection.find_one(query, {"_id": 1})
        if not existing:
            raise RuntimeError("Alert upsert failed")
        return str(existing["_id"]), False

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
