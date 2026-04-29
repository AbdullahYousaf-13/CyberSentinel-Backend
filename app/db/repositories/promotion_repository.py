from datetime import datetime
from typing import Any, Dict, Optional

from app.db.mongo import get_db


class PromotionRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("ml_promotions")

    async def upsert_promotion(
        self,
        fingerprint: str,
        classification: str,
        created_by: str,
        notes: Optional[str] = None,
    ) -> None:
        now = datetime.utcnow()
        await self._collection.update_one(
            {"fingerprint": fingerprint},
            {
                "$set": {
                    "fingerprint": fingerprint,
                    "classification": classification,
                    "active": True,
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

