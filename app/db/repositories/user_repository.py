from typing import Any, Dict, Optional

from app.db.mongo import get_db


class UserRepository:
    def __init__(self) -> None:
        self._collection = get_db().get_collection("users")

    async def create_user(self, payload: Dict[str, Any]) -> str:
        result = await self._collection.insert_one(payload)
        return str(result.inserted_id)

    async def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return await self._collection.find_one({"email": email})

    async def count_users(self) -> int:
        return await self._collection.count_documents({})
