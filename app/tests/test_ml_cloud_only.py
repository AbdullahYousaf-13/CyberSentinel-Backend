import asyncio
import socket
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.routes import ml as ml_routes
from app.schemas.ml import (
    BootstrapPreviewRequest,
    BootstrapReviewImportRequest,
    BootstrapReviewImportItem,
    ModelVersionActivateRequest,
    RetrainJobCreateRequest,
)
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


def test_create_retrain_job_uses_model_ops_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeOps:
        def __init__(self, _settings) -> None:
            return

        async def create_retrain_job(self, reason: str, requested_by: str, model_family: str, dataset_mode: str) -> str:
            assert reason == "manual"
            assert requested_by == "admin@test"
            assert model_family == "web_access"
            assert dataset_mode == "bootstrap_plus_feedback"
            return "job-1"

        async def get_retrain_job(self, _job_id: str):
            return {
                "id": "job-1",
                "status": "queued",
                "reason": "manual",
                "requested_by": "admin@test",
                "dataset_mode": "bootstrap_plus_feedback",
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "started_at": None,
                "finished_at": None,
                "metrics": {},
                "result": {},
                "error": None,
            }

    monkeypatch.setattr(ml_routes, "MLModelOpsService", _FakeOps)
    monkeypatch.setattr(ml_routes, "get_settings", lambda: object())
    payload = RetrainJobCreateRequest(reason="manual", dataset_mode="bootstrap_plus_feedback")
    result = asyncio.run(ml_routes.create_retrain_job(payload, current_user={"email": "admin@test"}))
    assert result.id == "job-1"
    assert result.dataset_mode == "bootstrap_plus_feedback"


def test_rollback_model_calls_model_ops_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeOps:
        def __init__(self, _settings) -> None:
            return

        async def rollback(self, target_version: str):
            return {"status": "ok", "active_version": target_version}

    monkeypatch.setattr(ml_routes, "MLModelOpsService", _FakeOps)
    monkeypatch.setattr(ml_routes, "get_settings", lambda: object())
    payload = ModelVersionActivateRequest(target_version="v1")
    result = asyncio.run(ml_routes.rollback_model(payload, current_user={"email": "admin@test"}))
    assert result["active_version"] == "v1"


def test_list_model_versions_translates_service_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailOps:
        def __init__(self, _settings) -> None:
            return

        async def list_versions(self):
            raise RuntimeError("MODEL_ADMIN_TOKEN is required for model ops")

    monkeypatch.setattr(ml_routes, "MLModelOpsService", _FailOps)
    monkeypatch.setattr(ml_routes, "get_settings", lambda: object())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(ml_routes.list_model_versions(current_user={"email": "admin@test"}))

    assert exc.value.status_code == 400
    assert "MODEL_ADMIN_TOKEN" in exc.value.detail


def test_list_suppressions_calls_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeSuppressions:
        async def list_suppressions(self, limit: int = 200):
            assert limit == 10
            now = datetime.utcnow()
            return [
                {
                    "fingerprint": "f" * 64,
                    "active": True,
                    "reason": "false_positive",
                    "created_by": "admin@test",
                    "created_at": now,
                    "updated_at": now,
                    "notes": "noise",
                }
            ]

    monkeypatch.setattr(ml_routes, "MLSuppressionService", _FakeSuppressions)
    result = asyncio.run(ml_routes.list_suppressions(current_user={"email": "admin@test"}, limit=10))
    assert len(result) == 1
    assert result[0].fingerprint == "f" * 64
    assert result[0].active is True


def test_deactivate_suppression_calls_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeSuppressions:
        async def deactivate(self, fingerprint: str):
            assert fingerprint == "abc"

    monkeypatch.setattr(ml_routes, "MLSuppressionService", _FakeSuppressions)
    result = asyncio.run(ml_routes.deactivate_suppression("abc", current_user={"email": "admin@test"}))
    assert result.fingerprint == "abc"
    assert result.active is False


def test_activate_suppression_calls_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeSuppressions:
        async def activate(self, fingerprint: str):
            assert fingerprint == "abc"

    monkeypatch.setattr(ml_routes, "MLSuppressionService", _FakeSuppressions)
    result = asyncio.run(ml_routes.activate_suppression("abc", current_user={"email": "admin@test"}))
    assert result.fingerprint == "abc"
    assert result.active is True


def test_preview_bootstrap_dataset_calls_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeBootstrap:
        async def preview_dataset(self, model_family: str, scan_limit: int, preview_limit: int, include_feedback_overrides: bool, min_class_support: int):
            assert model_family == "auth"
            assert scan_limit == 250
            assert preview_limit == 10
            assert include_feedback_overrides is True
            assert min_class_support == 5
            return {
                "model_family": "auth",
                "feature_schema_version": "auth_v1",
                "scanned_logs": 250,
                "usable_samples": 200,
                "skipped_logs": 50,
                "feedback_override_count": 3,
                "label_distribution": {"AUTH_ATTACK_GENERIC": 25, "BENIGN": 175},
                "raw_label_distribution": {"AUTH_BRUTE_FORCE": 5, "BENIGN": 175, "SUDO_POLICY_VIOLATION": 20},
                "verdict_distribution": {"confirmed_benign": 175, "confirmed_known_attack": 25},
                "thresholds": {
                    "benign_required": 1000,
                    "attack_required": 200,
                    "benign_available": 175,
                    "attack_available": 25,
                    "passed": False,
                },
                "rows": [],
            }

    monkeypatch.setattr(ml_routes, "WazuhBootstrapService", _FakeBootstrap)
    payload = BootstrapPreviewRequest(
        model_family="auth",
        scan_limit=250,
        preview_limit=10,
        include_feedback_overrides=True,
        min_class_support=5,
    )
    result = asyncio.run(ml_routes.preview_bootstrap_dataset(payload, current_user={"email": "admin@test"}))
    assert result.model_family == "auth"
    assert result.thresholds.passed is False


def test_import_bootstrap_reviews_calls_service(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeBootstrap:
        async def import_reviews(self, model_family: str, items, reviewed_by: str):
            assert model_family == "web_access"
            assert reviewed_by == "admin@test"
            assert items[0]["log_id"] == "l1"
            assert items[0]["review_verdict"] == "false_positive"
            return {
                "model_family": "web_access",
                "applied": 1,
                "skipped": 0,
                "failed": 0,
                "errors": [],
            }

    monkeypatch.setattr(ml_routes, "WazuhBootstrapService", _FakeBootstrap)
    payload = BootstrapReviewImportRequest(
        model_family="web_access",
        items=[BootstrapReviewImportItem(log_id="l1", review_verdict="false_positive", notes="noise")],
    )
    result = asyncio.run(ml_routes.import_bootstrap_reviews(payload, current_user={"email": "admin@test"}))
    assert result.applied == 1
    assert result.failed == 0
