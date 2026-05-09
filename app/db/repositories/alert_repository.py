from datetime import datetime
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

    async def count_alerts(self, filters: Optional[Dict[str, Any]] = None) -> int:
        query = filters or {}
        return await self._collection.count_documents(query)

    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(alert_id)})

    async def update_alert_fields(self, alert_id: str, updates: Dict[str, Any]) -> None:
        await self._collection.update_one({"_id": ObjectId(alert_id)}, {"$set": updates})

    async def get_alert_by_log_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"log_id": log_id})

    async def list_alerts_for_digest(
        self,
        severities: List[str],
        start_ts: datetime,
        end_ts: datetime,
        limit: int = 500,
    ) -> List[Dict[str, Any]]:
        query = {
            "severity": {"$in": severities},
            "created_at": {"$gt": start_ts, "$lte": end_ts},
        }
        cursor = self._collection.find(query).sort("created_at", 1).limit(limit)
        return await cursor.to_list(length=limit)

    async def list_alerts_for_analytics(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        cursor = self._collection.find(
            filters or {},
            {
                "_id": 0,
                "created_at": 1,
                "classification": 1,
                "alert_type": 1,
                "attack_type": 1,
                "type": 1,
                "severity": 1,
            },
        ).sort("created_at", 1)
        results: List[Dict[str, Any]] = []
        async for document in cursor:
            results.append(document)
        return results
