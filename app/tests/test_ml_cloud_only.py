import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routes.ml import rollback_models, retrain_models
from app.schemas.ml import RollbackRequest, TrainingDataRequest
from app.services.ml_service import MLService


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class _TestServer:
    def __init__(self) -> None:
        self._server = HTTPServer(("127.0.0.1", 0), _HealthHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def test_get_required_model_api_url_requires_value() -> None:
    settings = SimpleNamespace(model_api_url="  ")
    with pytest.raises(RuntimeError, match="MODEL_API_URL is required"):
        MLService.get_required_model_api_url(settings)


def test_get_required_model_api_url_requires_absolute_http_url() -> None:
    settings = SimpleNamespace(model_api_url="localhost:8010")
    with pytest.raises(RuntimeError, match="absolute http\\(s\\) URL"):
        MLService.get_required_model_api_url(settings)


def test_validate_cloud_model_reachable_success() -> None:
    with _TestServer() as server:
        asyncio.run(MLService.validate_cloud_model_reachable(server.url, 2))


def test_validate_cloud_model_reachable_failure() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp:
        temp.bind(("127.0.0.1", 0))
        port = temp.getsockname()[1]
    with pytest.raises(RuntimeError, match="not reachable or not healthy"):
        asyncio.run(MLService.validate_cloud_model_reachable(f"http://127.0.0.1:{port}", 1))


def test_retrain_endpoint_disabled_in_cloud_only_mode() -> None:
    payload = TrainingDataRequest(reason="x", features=[[0.0]], labels=[0])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(retrain_models(payload, current_user={"id": "test"}))
    assert exc.value.status_code == 501


def test_rollback_endpoint_disabled_in_cloud_only_mode() -> None:
    payload = RollbackRequest(target_version="v1")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(rollback_models(payload, current_user={"id": "test"}))
    assert exc.value.status_code == 501
