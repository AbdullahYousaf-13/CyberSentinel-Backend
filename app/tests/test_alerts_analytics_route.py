import asyncio
from datetime import datetime

from app.schemas.alert import MarkFalsePositiveRequest
from app.routes import alerts as alerts_route


def test_response_classification_returns_model_value_or_none() -> None:
    assert alerts_route._response_classification({"classification": "SSH_BRUTE"}) == "SSH_BRUTE"
    assert alerts_route._response_classification({"classification": "   "}) is None
    assert alerts_route._response_classification({"classification": "UNKNOWN_ATTACK"}) is None
    assert alerts_route._response_classification({"alert_type": "anomaly"}) is None


def test_map_alert_response_uses_legacy_log_summary_time_when_opened_at_missing() -> None:
    response = alerts_route._map_alert_response(
        {
            "_id": "64b64c9277f33a3f8c7d0e4a",
            "created_at": datetime(2026, 5, 12, 8, 51, 39),
            "log_id": "64b64c9277f33a3f8c7d0e4b",
            "alert_type": "anomaly",
            "severity": "medium",
            "metadata": {
                "log_summary": {
                    "event_time": "2026-05-11T16:00:11Z",
                }
            },
        }
    )

    assert response.opened_at.isoformat() == "2026-05-11T16:00:11+00:00"
    assert response.last_seen_at == response.opened_at


def test_get_alert_analytics_route_returns_empty_shape(monkeypatch) -> None:
    class _FakeAlertService:
        async def get_alert_analytics(self):
            return {
                "severity_counts": {"total": 0, "high": 0, "medium": 0, "low": 0},
                "trend": {"unit": "day", "points": []},
                "distribution": [],
                "total_alerts": 0,
                "first_alert_at": None,
                "last_alert_at": None,
                "window": {"start": None, "end": None, "bucket_unit": "day"},
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
                "severity_counts": {"total": 3, "high": 2, "medium": 1, "low": 0},
                "distribution": [
                    {"key": "quantum_probe", "label": "Quantum Probe", "count": 2, "percentage": 66.67},
                    {"key": "ssh_brute", "label": "Ssh Brute", "count": 1, "percentage": 33.33},
                ],
                "total_alerts": 3,
                "first_alert_at": datetime(2026, 1, 1, 0, 0, 0),
                "last_alert_at": datetime(2026, 1, 7, 23, 0, 0),
                "window": {
                    "start": datetime(2026, 1, 1, 0, 0, 0),
                    "end": datetime(2026, 1, 7, 23, 0, 0),
                    "bucket_unit": "week",
                },
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
