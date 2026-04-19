import logging
from typing import Optional
from urllib.parse import quote_plus
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.core.config import Settings

logger = logging.getLogger(__name__)

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


def resolve_mongo_uri(settings: Settings) -> str:
    direct_uri = (settings.mongo_uri or "").strip()
    if direct_uri:
        return direct_uri

    missing = []
    if not settings.mongo_user:
        missing.append("MONGO_USER")
    if not settings.mongo_password:
        missing.append("MONGO_PASSWORD")
    if not settings.mongo_host:
        missing.append("MONGO_HOST")

    if missing:
        raise RuntimeError(
            "MongoDB configuration is incomplete. Set MONGO_URI or provide "
            f"{', '.join(missing)}."
        )

    user = quote_plus(settings.mongo_user)
    password = quote_plus(settings.mongo_password)
    return f"mongodb+srv://{user}:{password}@{settings.mongo_host}/{settings.mongo_db}?retryWrites=true&w=majority"


async def connect_to_mongo(settings: Settings) -> None:
    global _client, _db
    uri = resolve_mongo_uri(settings)
    _client = AsyncIOMotorClient(uri)
    _db = _client[settings.mongo_db]
    try:
        await _client.admin.command("ping")
    except PyMongoError as exc:
        _client.close()
        _client = None
        _db = None
        raise RuntimeError(
            "MongoDB connection failed during startup. "
            "If you use Atlas, verify cluster status, Atlas IP Access List, "
            "and that outbound TLS to *.mongodb.net:27017 is allowed."
        ) from exc

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
    await db.get_collection("user").create_index("email", unique=True)
    await db.get_collection("user").create_index("email_verification_token_hash")
    await db.get_collection("user").create_index("password_reset_code_hash")
    await db.get_collection("logs").create_index([("timestamp", DESCENDING)])
    await db.get_collection("logs").create_index("source")
    await db.get_collection("logs").create_index("severity")
    await db.get_collection("logs").create_index(
        [("metadata.raw_ingest_key", ASCENDING)],
        unique=True,
        sparse=True,
    )
    await db.get_collection("logs").create_index([("ml_status", ASCENDING), ("timestamp", DESCENDING)])
    await db.get_collection("alerts").create_index([("created_at", DESCENDING)])
    await db.get_collection("alerts").create_index("severity")
    await db.get_collection("alerts").create_index("alert_type")
    try:
        await db.get_collection("alerts").create_index("log_id", unique=True)
    except PyMongoError as exc:
        logger.warning("Could not enforce unique alerts.log_id index: %s", exc)
        await db.get_collection("alerts").create_index("log_id")
    await db.get_collection("raw_wazuh_logs").create_index([("ingested_at", DESCENDING)])
    await db.get_collection("raw_wazuh_logs").create_index(
        [("ingest_key", ASCENDING)],
        unique=True,
        sparse=True,
    )
    await db.get_collection("raw_wazuh_logs").create_index(
        [("processing.status", ASCENDING), ("processing.next_retry_at", ASCENDING)]
    )
