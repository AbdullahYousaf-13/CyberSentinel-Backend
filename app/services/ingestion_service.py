import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from aiokafka import AIOKafkaConsumer

from app.core.config import Settings
from app.db.repositories.log_repository import LogRepository

logger = logging.getLogger(__name__)

_consumer: Optional[AIOKafkaConsumer] = None
_consumer_task: Optional[asyncio.Task] = None


class IngestionService:
    def __init__(self) -> None:
        self._logs = LogRepository()

    async def ingest_log(self, payload: Dict[str, Any], source: str) -> str:
        # Normalize payload so REST and Kafka share the same storage contract.
        normalized = {
            "timestamp": payload.get("timestamp", datetime.utcnow()),
            "source": source,
            "message": payload.get("message", ""),
            "metadata": payload.get("metadata", {}),
            "severity": payload.get("severity"),
            "ingested_at": datetime.utcnow(),
        }
        return await self._logs.create_log(normalized)


async def _consume_loop(settings: Settings) -> None:
    global _consumer
    ingestion = IngestionService()
    logger.info("Starting Kafka consumer")
    await _consumer.start()
    try:
        async for msg in _consumer:
            try:
                payload = json.loads(msg.value.decode("utf-8"))
                await ingestion.ingest_log(payload, source="kafka")
            except Exception as exc:
                logger.exception("Failed to ingest Kafka message: %s", exc)
    finally:
        await _consumer.stop()


async def start_kafka_consumer(settings: Settings) -> None:
    global _consumer, _consumer_task
    if _consumer_task:
        return
    _consumer = AIOKafkaConsumer(
        settings.kafka_topic,
        bootstrap_servers=settings.kafka_bootstrap_servers,
        group_id=settings.kafka_group_id,
        enable_auto_commit=True,
    )
    _consumer_task = asyncio.create_task(_consume_loop(settings))


async def stop_kafka_consumer() -> None:
    global _consumer_task
    if _consumer_task:
        _consumer_task.cancel()
        _consumer_task = None
