from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.core.websocket import websocket_router
from app.db.mongo import connect_to_mongo, close_mongo_connection, ensure_indexes
from app.routes import alerts, auth, health, logs, ml, users
from app.services.ingestion_service import start_kafka_consumer, stop_kafka_consumer
from app.services.ml_service import MLService


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings)

    app = FastAPI(title="CyberSentinel Backend", version="1.0.0")
    cors_setting = settings.cors_allow_origins.strip()
    if cors_setting == "*":
        cors_origins = ["*"]
        allow_credentials = False
    else:
        cors_origins = [
            origin.strip()
            for origin in settings.cors_allow_origins.split(",")
            if origin.strip()
        ]
        allow_credentials = True
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/health", tags=["health"])
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(users.router, prefix="/api/users", tags=["users"])
    app.include_router(ml.router, prefix="/api/ml", tags=["ml"])
    app.include_router(websocket_router, prefix="/api/ws", tags=["websocket"])

    @app.on_event("startup")
    async def on_startup() -> None:
        await connect_to_mongo(settings)
        await ensure_indexes()
        await MLService.initialize(settings)
        if settings.kafka_enabled:
            await start_kafka_consumer(settings)

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        if settings.kafka_enabled:
            await stop_kafka_consumer()
        await close_mongo_connection()

    return app


app = create_app()
