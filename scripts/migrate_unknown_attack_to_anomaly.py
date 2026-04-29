import asyncio
from datetime import datetime

from app.core.config import get_settings
from app.db.mongo import close_mongo_connection, connect_to_mongo, get_db


async def run() -> None:
    settings = get_settings()
    await connect_to_mongo(settings)
    db = get_db()
    logs = db.get_collection("logs")
    alerts = db.get_collection("alerts")

    now = datetime.utcnow()
    log_result = await logs.update_many(
        {"ml_result.classification": "UNKNOWN_ATTACK"},
        {
            "$set": {
                "ml_result.alert_type": "anomaly",
                "ml_result.classification": None,
                "metadata.legacy_prediction_label": "UNKNOWN_ATTACK",
                "metadata.unknown_migrated_at": now,
            }
        },
    )
    alert_result = await alerts.update_many(
        {"classification": "UNKNOWN_ATTACK"},
        {
            "$set": {
                "alert_type": "anomaly",
                "classification": None,
                "metadata.legacy_prediction_label": "UNKNOWN_ATTACK",
                "metadata.unknown_migrated_at": now,
            }
        },
    )
    print(
        f"Updated logs={log_result.modified_count}, alerts={alert_result.modified_count}"
    )
    await close_mongo_connection()


if __name__ == "__main__":
    asyncio.run(run())

