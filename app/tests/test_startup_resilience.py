from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import main as main_module


def test_startup_continues_when_cloud_model_readiness_fails(monkeypatch) -> None:
    settings = SimpleNamespace(
        app_env="test",
        debug_mode=False,
        detailed_logging=False,
        cors_allow_origins="http://localhost:3000",
        frontend_base_url="http://localhost:3000",
    )

    async def failing_initialize(_settings) -> None:
        raise RuntimeError("rate limited")

    async def noop(*_args, **_kwargs) -> None:
        return None

    class _FakeModelOpsService:
        def __init__(self, _settings) -> None:
            return

        async def recover_incomplete_jobs(self) -> None:
            return None

    monkeypatch.setattr(main_module, "get_settings", lambda: settings)
    monkeypatch.setattr(main_module.MLService, "initialize", failing_initialize)
    monkeypatch.setattr(main_module, "connect_to_mongo", noop)
    monkeypatch.setattr(main_module, "ensure_indexes", noop)
    monkeypatch.setattr(main_module, "MLModelOpsService", _FakeModelOpsService)
    monkeypatch.setattr(main_module, "start_raw_wazuh_background_worker", noop)
    monkeypatch.setattr(main_module, "start_notification_digest_worker", noop)
    monkeypatch.setattr(main_module, "stop_notification_digest_worker", noop)
    monkeypatch.setattr(main_module, "stop_raw_wazuh_background_worker", noop)
    monkeypatch.setattr(main_module, "close_mongo_connection", noop)

    app = main_module.create_app()

    with TestClient(app) as client:
        response = client.get("/api/health/")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
