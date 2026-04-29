import asyncio
from datetime import datetime

from app.schemas.alert import MarkFalsePositiveRequest
from app.routes import alerts as alerts_route


def test_response_classification_returns_model_value_or_none() -> None:
    assert alerts_route._response_classification({"classification": "SSH_BRUTE"}) == "SSH_BRUTE"
    assert alerts_route._response_classification({"classification": "   "}) is None
    assert alerts_route._response_classification({"classification": "UNKNOWN_ATTACK"}) is None
    assert alerts_route._response_classification({"alert_type": "anomaly"}) is None


def test_get_alert_analytics_route_returns_empty_shape(monkeypatch) -> None:
    class _FakeAlertService:
        async def get_alert_analytics(self):
            return {
                "trend": {"unit": "day", "points": []},
                "distribution": [],
                "total_alerts": 0,
                "first_alert_at": None,
                "last_alert_at": None,
            }

    monkeypatch.setattr(alerts_route, "AlertService", _FakeAlertService)
    response = asyncio.run(alerts_route.get_alert_analytics(current_user={"id": "u1"}))

    assert response.total_alerts == 0
    assert response.trend.unit == "day"
    assert response.trend.points == []
    assert response.distribution == []


def test_get_alert_analytics_route_keeps_dynamic_distribution_types(monkeypatch) -> None:
    class _FakeAlertService:
        async def get_alert_analytics(self):
            return {
                "trend": {
                    "unit": "week",
                    "points": [
                        {
                            "bucket_start": datetime(2026, 1, 1, 0, 0, 0),
                            "bucket_end": datetime(2026, 1, 8, 0, 0, 0),
                            "label": "Week of 2026-01-01",
                            "count": 3,
                        }
                    ],
                },
                "distribution": [
                    {"key": "quantum_probe", "label": "Quantum Probe", "count": 2, "percentage": 66.67},
                    {"key": "ssh_brute", "label": "Ssh Brute", "count": 1, "percentage": 33.33},
                ],
                "total_alerts": 3,
                "first_alert_at": datetime(2026, 1, 1, 0, 0, 0),
                "last_alert_at": datetime(2026, 1, 7, 23, 0, 0),
            }

    monkeypatch.setattr(alerts_route, "AlertService", _FakeAlertService)
    response = asyncio.run(alerts_route.get_alert_analytics(current_user={"id": "u1"}))

    assert response.total_alerts == 3
    assert response.distribution[0].key == "quantum_probe"
    assert response.distribution[0].label == "Quantum Probe"
    assert response.trend.points[0].count == 3


def test_mark_false_positive_route_returns_fingerprint(monkeypatch) -> None:
    class _FakeAlertService:
        async def mark_false_positive(self, alert_id: str, reviewed_by: str, notes: str | None = None):
            assert alert_id == "a1"
            assert reviewed_by == "admin@test"
            assert notes == "expected health checks"
            return {"alert_id": "a1", "fingerprint": "f" * 64}

    monkeypatch.setattr(alerts_route, "AlertService", _FakeAlertService)
    payload = MarkFalsePositiveRequest(notes="expected health checks")
    response = asyncio.run(
        alerts_route.mark_false_positive(
            alert_id="a1",
            payload=payload,
            current_user={"email": "admin@test"},
        )
    )

    assert response.alert_id == "a1"
    assert response.fingerprint == "f" * 64
