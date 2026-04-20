import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.db.repositories.log_repository import LogRepository
from app.routes import ml as ml_routes
from app.schemas.ml import BatchInferenceRequest
from app.services.ingestion_service import IngestionService
from app.services.ml_service import MLService


class _FakeCursor:
    def __init__(self, docs):
        self._docs = docs

    def sort(self, *_args, **_kwargs):
        return self

    def limit(self, limit):
        self._limit = limit
        return self

    async def to_list(self, length):
        return self._docs[:length]


class _FakeCollection:
    def __init__(self, docs):
        self._docs = docs
        self.last_query = None

    def find(self, query=None):
        self.last_query = query
        return _FakeCursor(self._docs)


class _FakeLogRepository:
    def __init__(self, logs):
        self._logs = logs
        self.done_calls = []
        self.error_calls = []
        self.created_payload = None

    async def fetch_batch(self, limit):
        return self._logs[:limit]

    async def mark_ml_done(self, log_id, result, model_version):
        self.done_calls.append((log_id, result, model_version))

    async def mark_ml_error(self, log_id, error):
        self.error_calls.append((log_id, error))

    async def create_log(self, payload):
        self.created_payload = payload
        return "created-id"


class _FakeAlertService:
    def __init__(self):
        self.calls = []

    async def create_or_get_alert(self, **kwargs):
        self.calls.append(kwargs)
        return "alert-id"


def test_fetch_batch_filters_to_unprocessed_logs() -> None:
    repo = LogRepository.__new__(LogRepository)
    repo._collection = _FakeCollection([{"_id": "a"}])  # type: ignore[attr-defined]

    logs = asyncio.run(repo.fetch_batch(10))

    assert len(logs) == 1
    assert repo._collection.last_query == {  # type: ignore[attr-defined]
        "$or": [
            {"ml_status": {"$exists": False}},
            {"ml_status": "pending"},
            {"ml_status": "error"},
        ]
    }


def test_ingest_log_sets_pending_ml_status() -> None:
    fake_logs = _FakeLogRepository([])
    service = IngestionService.__new__(IngestionService)
    service._logs = fake_logs

    log_id = asyncio.run(
        service.ingest_log(
            {
                "timestamp": datetime(2026, 1, 1),
                "message": "hello",
                "metadata": {},
                "severity": "low",
            },
            source="api",
        )
    )

    assert log_id == "created-id"
    assert fake_logs.created_payload is not None
    assert fake_logs.created_payload["ml_status"] == "pending"


def test_run_batch_inference_marks_done_and_error_and_continues() -> None:
    logs = [
        {"_id": "log-1", "source": "api", "message": "benign case"},
        {"_id": "log-2", "source": "api", "message": "bad case"},
    ]
    fake_logs = _FakeLogRepository(logs)
    fake_alerts = _FakeAlertService()
    service = MLService.__new__(MLService)
    service._settings = SimpleNamespace(
        model_api_url="http://127.0.0.1:8010",
        model_api_timeout_seconds=5,
        anomaly_score_threshold=0.65,
    )
    service._logs = fake_logs
    service._alerts = fake_alerts

    async def fake_infer_single(log):
        if log["_id"] == "log-1":
            return {"alert_type": "benign", "classification": None, "score": 0.0}, "cloud-api"
        raise HTTPException(status_code=502, detail="cloud failure")

    service.infer_single_log = fake_infer_single  # type: ignore[method-assign]

    result = asyncio.run(service.run_batch_inference(10))

    assert result == {"processed": 2, "alerts": 0}
    assert fake_logs.done_calls == [
        ("log-1", {"alert_type": "benign", "classification": None, "score": 0.0}, "cloud-api")
    ]
    assert len(fake_logs.error_calls) == 1
    assert fake_logs.error_calls[0][0] == "log-2"
    assert "cloud failure" in fake_logs.error_calls[0][1]
    assert fake_alerts.calls == []


def test_run_batch_inference_creates_alert_for_non_benign() -> None:
    logs = [{"_id": "log-3", "source": "api", "message": None}]
    fake_logs = _FakeLogRepository(logs)
    fake_alerts = _FakeAlertService()
    service = MLService.__new__(MLService)
    service._settings = SimpleNamespace(
        model_api_url="http://127.0.0.1:8010",
        model_api_timeout_seconds=5,
        anomaly_score_threshold=0.65,
    )
    service._logs = fake_logs
    service._alerts = fake_alerts

    async def fake_infer_single(_log):
        return {"alert_type": "known_attack", "classification": "SSH_BRUTE", "score": 1.0}, "cloud-api"

    service.infer_single_log = fake_infer_single  # type: ignore[method-assign]

    result = asyncio.run(service.run_batch_inference(10))

    assert result == {"processed": 1, "alerts": 1}
    assert len(fake_logs.done_calls) == 1
    assert fake_logs.error_calls == []
    assert len(fake_alerts.calls) == 1
    assert fake_alerts.calls[0]["log_id"] == "log-3"
    assert fake_alerts.calls[0]["metadata"]["message"] == ""


def test_batch_infer_rejects_parallel_runs_with_409(monkeypatch: pytest.MonkeyPatch) -> None:
    class _SlowMLService:
        def __init__(self, _settings) -> None:
            return

        async def run_batch_inference(self, batch_size: int) -> dict:
            await asyncio.sleep(0.15)
            return {"processed": batch_size, "alerts": 0}

    monkeypatch.setattr(ml_routes, "MLService", _SlowMLService)
    monkeypatch.setattr(ml_routes, "get_settings", lambda: object())
    ml_routes._batch_infer_state_lock = asyncio.Lock()
    ml_routes._batch_infer_in_progress = False
    payload = BatchInferenceRequest(batch_size=1)

    async def _run() -> None:
        first_task = asyncio.create_task(ml_routes.batch_infer(payload, current_user={"id": "u"}))
        await asyncio.sleep(0.02)
        with pytest.raises(HTTPException) as exc:
            await ml_routes.batch_infer(payload, current_user={"id": "u"})
        first_result = await first_task
        assert first_result == {"processed": 1, "alerts": 0}
        assert exc.value.status_code == 409
        assert exc.value.detail == "batch inference already running"
        assert ml_routes._batch_infer_in_progress is False

    asyncio.run(_run())


def test_batch_infer_releases_guard_after_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailingMLService:
        def __init__(self, _settings) -> None:
            return

        async def run_batch_inference(self, _batch_size: int) -> dict:
            raise RuntimeError("boom")

    class _SuccessMLService:
        def __init__(self, _settings) -> None:
            return

        async def run_batch_inference(self, batch_size: int) -> dict:
            return {"processed": batch_size, "alerts": 0}

    monkeypatch.setattr(ml_routes, "get_settings", lambda: object())
    ml_routes._batch_infer_state_lock = asyncio.Lock()
    ml_routes._batch_infer_in_progress = False
    payload = BatchInferenceRequest(batch_size=2)

    monkeypatch.setattr(ml_routes, "MLService", _FailingMLService)
    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(ml_routes.batch_infer(payload, current_user={"id": "u"}))

    monkeypatch.setattr(ml_routes, "MLService", _SuccessMLService)
    result = asyncio.run(ml_routes.batch_infer(payload, current_user={"id": "u"}))
    assert result == {"processed": 2, "alerts": 0}
    assert ml_routes._batch_infer_in_progress is False
