from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.db.mongo import get_db


class LogRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("logs")

    async def create_log(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def fetch_batch(self, limit: int) -> List[Dict[str, Any]]:
        cursor = self._collection.find().sort("timestamp", 1).limit(limit)
        return await cursor.to_list(length=limit)

    async def list_logs(
        self,
        limit: int,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        query = filters or {}
        cursor = (
            self._collection.find(query)
            .sort("timestamp", -1)
            .skip(offset)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def get_by_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(log_id)})
