from datetime import datetime
from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, ReturnDocument, UpdateOne
from app.db.mongo import get_db


class RawWazuhLogRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("raw_wazuh_logs")

    async def upsert_batch(self, logs: List[Dict[str, Any]], sent_at_ms: int) -> Dict[str, Any]:
        if not logs:
            return {"inserted": 0, "duplicates": 0, "inserted_keys": []}

        now = datetime.utcnow()
        operations = []
        for entry in logs:
            operations.append(
                UpdateOne(
                    {"ingest_key": entry["ingest_key"]},
                    {
                        "$setOnInsert": {
                            "ingest_key": entry["ingest_key"],
                            "payload": entry["payload"],
                            "ingest_meta": entry["ingest_meta"],
                            "sent_at": sent_at_ms,
                            "ingested_at": now,
                            "processing": {
                                "status": "pending",
                                "attempts": 0,
                                "next_retry_at": now,
                                "last_error": None,
                                "updated_at": now,
                            },
                        }
                    },
                    upsert=True,
                )
            )

        result = await self._collection.bulk_write(operations, ordered=False)
        inserted_indices = set((result.upserted_ids or {}).keys())
        inserted_keys = [logs[i]["ingest_key"] for i in sorted(inserted_indices)]
        inserted = len(inserted_keys)
        return {"inserted": inserted, "duplicates": len(logs) - inserted, "inserted_keys": inserted_keys}

    async def claim_next_for_processing(self) -> Optional[Dict[str, Any]]:
        now = datetime.utcnow()
        return await self._collection.find_one_and_update(
            {
                "processing.status": {"$in": ["pending", "error"]},
                "processing.next_retry_at": {"$lte": now},
            },
            {
                "$set": {
                    "processing.status": "processing",
                    "processing.processing_started_at": now,
                    "processing.updated_at": now,
                },
                "$inc": {"processing.attempts": 1},
            },
            sort=[("processing.next_retry_at", ASCENDING), ("ingested_at", ASCENDING)],
            return_document=ReturnDocument.AFTER,
        )

    async def mark_done(self, ingest_key: str, engineered_log_id: str) -> None:
        now = datetime.utcnow()
        await self._collection.update_one(
            {"ingest_key": ingest_key},
            {
                "$set": {
                    "processing.status": "done",
                    "processing.done_at": now,
                    "processing.updated_at": now,
                    "processing.last_error": None,
                    "processing.engineered_log_id": engineered_log_id,
                }
            },
        )

    async def mark_error(self, ingest_key: str, next_retry_at: datetime, error: str) -> None:
        now = datetime.utcnow()
        await self._collection.update_one(
            {"ingest_key": ingest_key},
            {
                "$set": {
                    "processing.status": "error",
                    "processing.next_retry_at": next_retry_at,
                    "processing.last_error": error[:1000],
                    "processing.updated_at": now,
                }
            },
        )
