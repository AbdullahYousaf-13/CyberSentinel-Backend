from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.db.mongo import get_db


class LogRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("logs")

    async def create_log(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def upsert_engineered_log(self, raw_ingest_key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        query = {"metadata.raw_ingest_key": raw_ingest_key}
        result = await self._collection.update_one(query, {"$setOnInsert": payload}, upsert=True)
        if result.upserted_id is not None:
            created = await self._collection.find_one({"_id": result.upserted_id})
            if created:
                return created
        found = await self._collection.find_one(query)
        if not found:
            raise RuntimeError("Engineered log upsert failed")
        return found

    async def fetch_batch(self, limit: int) -> List[Dict[str, Any]]:
        query = {
            "$or": [
                {"ml_status": {"$exists": False}},
                {"ml_status": "pending"},
                {"ml_status": "error"},
            ]
        }
        cursor = self._collection.find(query).sort("timestamp", 1).limit(limit)
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

    async def count_logs(self, filters: Optional[Dict[str, Any]] = None) -> int:
        query = filters or {}
        return await self._collection.count_documents(query)

    async def get_by_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(log_id)})

    async def mark_ml_done(self, log_id: ObjectId, result: Dict[str, Any], model_version: str) -> None:
        await self._collection.update_one(
            {"_id": log_id},
            {
                "$set": {
                    "ml_status": "done",
                    "ml_processed_at": datetime.utcnow(),
                    "ml_result": result,
                    "ml_model_version": model_version,
                },
                "$unset": {"ml_error": ""},
            },
        )

    async def mark_ml_error(self, log_id: ObjectId, error: str) -> None:
        await self._collection.update_one(
            {"_id": log_id},
            {
                "$set": {
                    "ml_status": "error",
                    "ml_processed_at": datetime.utcnow(),
                    "ml_error": error[:1000],
                },
            },
        )
