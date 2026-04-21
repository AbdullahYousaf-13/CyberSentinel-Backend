from datetime import datetime
from typing import Any, Dict, Optional

from bson import ObjectId

from app.db.mongo import get_db


class UserRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("user")

    async def create_user(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"email": email})

    async def get_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"_id": ObjectId(user_id)})

    async def list_users(self, limit: int) -> list[Dict[str, Any]]:
        cursor = self._collection.find().sort("created_at", 1).limit(limit)
        return await cursor.to_list(length=limit)

    async def count_users(self) -> int:
        return await self._collection.count_documents({})

    async def update_notification_preferences(self, user_id: str, prefs: Dict[str, Any]) -> None:
        await self._collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"notification_prefs": prefs}},
        )

    async def list_immediate_notification_users(
        self,
        severity: str,
        alert_created_at: datetime,
        limit: int = 200,
    ) -> list[Dict[str, Any]]:
        query = {
            "notification_prefs.email_enabled": True,
            "notification_prefs.frequency": "immediate",
            "notification_prefs.severities": severity,
            "notification_prefs.cursor_at": {"$lte": alert_created_at},
            "email_verified": True,
        }
        cursor = self._collection.find(query).limit(limit)
        return await cursor.to_list(length=limit)

    async def list_due_daily_digest_users(
        self,
        now_utc: datetime,
        limit: int = 200,
    ) -> list[Dict[str, Any]]:
        query = {
            "notification_prefs.email_enabled": True,
            "notification_prefs.frequency": "daily",
            "notification_prefs.next_digest_at": {"$lte": now_utc},
            "email_verified": True,
        }
        cursor = self._collection.find(query).limit(limit)
        return await cursor.to_list(length=limit)

    async def update_digest_schedule(
        self,
        user_id: str,
        next_digest_at: datetime,
        last_digest_sent_at: Optional[datetime] = None,
    ) -> None:
        updates: Dict[str, Any] = {"notification_prefs.next_digest_at": next_digest_at}
        if last_digest_sent_at is not None:
            updates["notification_prefs.last_digest_sent_at"] = last_digest_sent_at
        await self._collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": updates},
        )
