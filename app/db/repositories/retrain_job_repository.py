from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.db.mongo import get_db


class RetrainJobRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("ml_retrain_jobs")

    async def create_job(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(job_id)})

    async def list_jobs(self, limit: int = 20) -> List[Dict[str, Any]]:
        cursor = self._collection.find({}).sort("created_at", -1).limit(limit)
        return await cursor.to_list(length=limit)

    async def update_job(self, job_id: str, updates: Dict[str, Any]) -> None:
        updates = dict(updates)
        updates["updated_at"] = datetime.utcnow()
        await self._collection.update_one({"_id": ObjectId(job_id)}, {"$set": updates})

