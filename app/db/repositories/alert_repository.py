from datetime import datetime
from typing import Any, Dict, List, Optional

from bson import ObjectId
from pymongo import ASCENDING

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

    async def list_alerts_for_analytics(self) -> List[Dict[str, Any]]:
        cursor = self._collection.find(
            {},
            {
                "_id": 0,
                "created_at": 1,
                "classification": 1,
                "alert_type": 1,
                "attack_type": 1,
                "type": 1,
            },
        ).sort("created_at", 1)
        results: List[Dict[str, Any]] = []
        async for document in cursor:
            results.append(document)
        return results

    async def count_alerts(self, filters: Optional[Dict[str, Any]] = None) -> int:
        query = filters or {}
        return await self._collection.count_documents(query)

    async def aggregate_severity_counts(self) -> Dict[str, int]:
        pipeline = [
            {
                "$group": {
                    "_id": {"$toLower": {"$ifNull": ["$severity", ""]}},
                    "count": {"$sum": 1},
                }
            }
        ]
        counts = {"total": 0, "high": 0, "medium": 0, "low": 0}
        async for row in self._collection.aggregate(pipeline):
            severity = str(row.get("_id") or "")
            count = int(row.get("count") or 0)
            counts["total"] += count
            if severity in {"high", "critical"}:
                counts["high"] += count
            elif severity == "medium":
                counts["medium"] += count
            else:
                counts["low"] += count
        return counts

    async def aggregate_distribution(self) -> List[Dict[str, Any]]:
        project_stage = {
            "$project": {
                "classification": {"$trim": {"input": {"$ifNull": ["$classification", ""]}}},
                "alert_type": {"$trim": {"input": {"$ifNull": ["$alert_type", ""]}}},
                "attack_type": {"$trim": {"input": {"$ifNull": ["$attack_type", ""]}}},
                "type": {"$trim": {"input": {"$ifNull": ["$type", ""]}}},
            }
        }
        group_stage = {
            "$group": {
                "_id": {
                    "$let": {
                        "vars": {
                            "primary": {"$toLower": "$classification"},
                            "secondary": {"$toLower": "$alert_type"},
                            "tertiary": {"$toLower": "$attack_type"},
                            "quaternary": {"$toLower": "$type"},
                        },
                        "in": {
                            "$switch": {
                                "branches": [
                                    {
                                        "case": {
                                            "$and": [
                                                {"$ne": ["$$primary", ""]},
                                                {"$not": {"$in": ["$$primary", ["n/a", "na", "none", "null", "undefined", "unknown_attack"]]}},
                                            ]
                                        },
                                        "then": "$$primary",
                                    },
                                    {"case": {"$ne": ["$$secondary", ""]}, "then": "$$secondary"},
                                    {"case": {"$ne": ["$$tertiary", ""]}, "then": "$$tertiary"},
                                    {"case": {"$ne": ["$$quaternary", ""]}, "then": "$$quaternary"},
                                ],
                                "default": "uncategorized",
                            }
                        },
                    }
                },
                "count": {"$sum": 1},
            }
        }
        cursor = self._collection.aggregate([project_stage, group_stage, {"$sort": {"count": -1, "_id": ASCENDING}}])
        rows: List[Dict[str, Any]] = []
        async for row in cursor:
            rows.append({"key": str(row.get("_id") or "uncategorized"), "count": int(row.get("count") or 0)})
        return rows

    async def aggregate_trend(self, unit: str, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        if unit == "hour":
            date_format = "%Y-%m-%d %H:00"
        elif unit == "day":
            date_format = "%Y-%m-%d"
        elif unit == "week":
            date_format = "%G-W%V"
        else:
            date_format = "%Y-%m"

        pipeline = [
            {"$match": {"created_at": {"$gte": start, "$lte": end}}},
            {
                "$group": {
                    "_id": {"$dateToString": {"format": date_format, "date": "$created_at"}},
                    "count": {"$sum": 1},
                    "bucket_start": {"$min": "$created_at"},
                }
            },
            {"$sort": {"bucket_start": ASCENDING}},
        ]
        rows: List[Dict[str, Any]] = []
        async for row in self._collection.aggregate(pipeline):
            rows.append(
                {
                    "label": str(row.get("_id")),
                    "count": int(row.get("count") or 0),
                    "bucket_start": row.get("bucket_start"),
                }
            )
        return rows

    async def min_max_created_at(self) -> Dict[str, Optional[datetime]]:
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "min_created_at": {"$min": "$created_at"},
                    "max_created_at": {"$max": "$created_at"},
                }
            }
        ]
        row = None
        async for doc in self._collection.aggregate(pipeline):
            row = doc
            break
        if not row:
            return {"min_created_at": None, "max_created_at": None}
        return {
            "min_created_at": row.get("min_created_at"),
            "max_created_at": row.get("max_created_at"),
        }
