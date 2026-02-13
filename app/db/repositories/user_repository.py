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
