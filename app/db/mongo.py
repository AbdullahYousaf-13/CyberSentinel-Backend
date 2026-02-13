from typing import Optional

from pymongo import ASCENDING, DESCENDING

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import Settings

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


async def connect_to_mongo(settings: Settings) -> None:
    global _client, _db
    _client = AsyncIOMotorClient(settings.mongo_uri)
    _db = _client[settings.mongo_db]


async def close_mongo_connection() -> None:
    global _client
    if _client:
        _client.close()


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("MongoDB not initialized")
    return _db


async def ensure_indexes() -> None:
    db = get_db()
    await db.get_collection("users").create_index("email", unique=True)
    await db.get_collection("users").create_index("email_verification_token_hash")
    await db.get_collection("users").create_index("password_reset_code_hash")
    await db.get_collection("logs").create_index([("timestamp", DESCENDING)])
    await db.get_collection("logs").create_index("source")
    await db.get_collection("logs").create_index("severity")
    await db.get_collection("alerts").create_index([("created_at", DESCENDING)])
    await db.get_collection("alerts").create_index("severity")
    await db.get_collection("alerts").create_index("alert_type")
    await db.get_collection("alerts").create_index("log_id")
