import asyncio
import contextlib
import logging
import time
from typing import Awaitable, Callable, TypeVar

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.core.websocket import websocket_router
from app.db.mongo import connect_to_mongo, close_mongo_connection, ensure_indexes
from app.routes import alerts, auth, health, logs, ml, raw_wazuh_logs, users
from app.services.ml_service import MLService
from app.services.ml_model_ops_service import MLModelOpsService
from app.services.notification_service import (
    start_notification_digest_worker,
    stop_notification_digest_worker,
)
from app.services.raw_wazuh_pipeline_service import (
    start_raw_wazuh_background_worker,
    stop_raw_wazuh_background_worker,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")
RENDER_FRONTEND_ORIGIN = "https://cybersentinel-frontend.onrender.com"


async def _timed_startup_step(name: str, action: Callable[[], Awaitable[T]]) -> T:
    started = time.monotonic()
    logger.info("Startup step started: %s", name)
    try:
        result = await action()
    except Exception:
        elapsed_ms = round((time.monotonic() - started) * 1000)
        logger.exception("Startup step failed after %sms: %s", elapsed_ms, name)
        raise
    elapsed_ms = round((time.monotonic() - started) * 1000)
    logger.info("Startup step completed after %sms: %s", elapsed_ms, name)
    return result


async def _background_cloud_model_readiness(settings: Settings) -> None:
    try:
        await _timed_startup_step("cloud model readiness", lambda: MLService.initialize(settings))
    except Exception:
        logger.exception(
            "Cloud model readiness check failed; continuing startup so auth, health, "
            "logs, and alerts routes remain available. ML inference will fail until "
            "MODEL_API_URL becomes healthy."
        )


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings)

    app = FastAPI(title="CyberSentinel Backend", version="1.0.0")
    cors_setting = (settings.cors_allow_origins or "").strip()
    if cors_setting == "*" or not cors_setting:
        # Use explicit dev origins instead of wildcard so auth-protected routes
        # consistently include CORS headers for browser fetch requests.
        cors_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]
        frontend_origin = (settings.frontend_base_url or "").strip()
        if frontend_origin and frontend_origin not in cors_origins:
            cors_origins.append(frontend_origin)
    else:
        cors_origins = [
            origin.strip()
            for origin in settings.cors_allow_origins.split(",")
            if origin.strip()
        ]
    for origin in ((settings.frontend_base_url or "").strip(), RENDER_FRONTEND_ORIGIN):
        if origin and origin not in cors_origins:
            cors_origins.append(origin)
    allow_credentials = True
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    app.include_router(health.router, prefix="/api/health", tags=["health"])
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(raw_wazuh_logs.router, prefix="/api", tags=["raw-wazuh"])
    app.include_router(logs.router, prefix="/api/logs", tags=["logs"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(users.router, prefix="/api/users", tags=["users"])
    app.include_router(ml.router, prefix="/api/ml", tags=["ml"])
    app.include_router(websocket_router, prefix="/api/ws", tags=["websocket"])

    @app.on_event("startup")
    async def on_startup() -> None:
        app.state.cloud_model_readiness_task = asyncio.create_task(
            _background_cloud_model_readiness(settings),
            name="cloud-model-readiness",
        )
        await _timed_startup_step("mongo connection", lambda: connect_to_mongo(settings))
        await _timed_startup_step("mongo indexes", ensure_indexes)
        await _timed_startup_step(
            "model job recovery",
            lambda: MLModelOpsService(settings).recover_incomplete_jobs(),
        )
        await _timed_startup_step(
            "raw wazuh workers",
            lambda: start_raw_wazuh_background_worker(settings),
        )
        await _timed_startup_step(
            "notification digest worker",
            lambda: start_notification_digest_worker(settings),
        )

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        task = getattr(app.state, "cloud_model_readiness_task", None)
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await stop_notification_digest_worker()
        await stop_raw_wazuh_background_worker()
        await close_mongo_connection()

    return app


app = create_app()
