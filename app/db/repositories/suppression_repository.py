from datetime import datetime
from typing import Any, Dict, List, Optional

from app.db.mongo import get_db


class SuppressionRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("ml_suppressions")

    async def upsert_suppression(
        self,
        fingerprint: str,
        reason: str,
        created_by: str,
        notes: Optional[str] = None,
    ) -> None:
        now = datetime.utcnow()
        await self._collection.update_one(
            {"fingerprint": fingerprint},
            {
                "$set": {
                    "fingerprint": fingerprint,
                    "active": True,
                    "reason": reason.strip()[:120],
                    "created_by": created_by,
                    "notes": notes,
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "created_at": now,
                },
            },
            upsert=True,
        )

    async def find_active(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"fingerprint": fingerprint, "active": True})

    async def set_active(self, fingerprint: str, active: bool) -> bool:
        result = await self._collection.update_one(
            {"fingerprint": fingerprint},
            {"$set": {"active": active, "updated_at": datetime.utcnow()}},
        )
        return result.matched_count > 0

    async def list_suppressions(self, limit: int = 200) -> List[Dict[str, Any]]:
        cursor = self._collection.find({}).sort("updated_at", -1).limit(limit)
        return await cursor.to_list(length=limit)

