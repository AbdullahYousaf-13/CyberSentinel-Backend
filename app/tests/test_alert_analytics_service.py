import asyncio
from datetime import datetime, timedelta

from app.services.alert_service import (
    AlertService,
    _merge_trend_points,
    _normalize_classification,
    _resolve_distribution_key,
    _select_trend_unit,
)


class _FakeAlertRepository:
    def __init__(self, rows):
        self._rows = rows

    async def list_alerts_for_analytics(self):
        return self._rows


def _build_service(rows):
    service = AlertService.__new__(AlertService)
    service._alerts = _FakeAlertRepository(rows)
    return service


def test_resolve_distribution_key_prefers_classification_then_fallbacks() -> None:
    assert _resolve_distribution_key({"classification": "SSH_BRUTE", "alert_type": "known_attack"}) == "ssh_brute"
    assert _resolve_distribution_key({"classification": "0", "alert_type": "unknown_sensor_flag"}) == "unknown_sensor_flag"
    assert _resolve_distribution_key({"classification": "N/A", "alert_type": None, "attack_type": "", "type": "  "}) == "uncategorized"


def test_select_trend_unit_thresholds() -> None:
    assert _select_trend_unit(timedelta(days=1)) == "hour"
    assert _select_trend_unit(timedelta(days=30)) == "day"
    assert _select_trend_unit(timedelta(days=365)) == "week"
    assert _select_trend_unit(timedelta(days=1000)) == "month"


def test_merge_trend_points_reduces_to_target() -> None:
    points = []
    start = datetime(2026, 1, 1, 0, 0, 0)
    for idx in range(25):
        point_start = start + timedelta(days=idx)
        points.append(
            {
                "bucket_start": point_start,
                "bucket_end": point_start + timedelta(days=1),
                "label": f"day-{idx}",
                "count": 1,
            }
        )

    merged = _merge_trend_points(points, 12)
    assert len(merged) == 12
    assert sum(item["count"] for item in merged) == 25
    assert merged[0]["bucket_start"] == points[0]["bucket_start"]
    assert merged[-1]["bucket_end"] == points[-1]["bucket_end"]


def test_normalize_classification_keeps_model_label_only() -> None:
    assert _normalize_classification("SSH_BRUTE") == "SSH_BRUTE"
    assert _normalize_classification("  ") is None
    assert _normalize_classification(None) is None


def test_get_alert_analytics_returns_empty_payload_for_no_alerts() -> None:
    service = _build_service([])
    payload = asyncio.run(service.get_alert_analytics())

    assert payload["total_alerts"] == 0
    assert payload["trend"]["points"] == []
    assert payload["distribution"] == []
    assert payload["first_alert_at"] is None
    assert payload["last_alert_at"] is None


def test_get_alert_analytics_short_span_uses_hour_buckets() -> None:
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    rows = [
        {"created_at": now - timedelta(hours=20), "classification": "SSH_BRUTE"},
        {"created_at": now - timedelta(hours=5), "alert_type": "credential_attack"},
        {"created_at": now - timedelta(hours=1), "classification": "N/A", "alert_type": "new_signal"},
    ]
    service = _build_service(rows)
    payload = asyncio.run(service.get_alert_analytics())

    assert payload["trend"]["unit"] == "hour"
    assert len(payload["trend"]["points"]) <= 12
    assert sum(point["count"] for point in payload["trend"]["points"]) == 3
    keys = [item["key"] for item in payload["distribution"]]
    assert "ssh_brute" in keys
    assert "credential_attack" in keys
    assert "new_signal" in keys


def test_get_alert_analytics_long_span_uses_month_and_merges_to_12() -> None:
    base = datetime(2022, 1, 1, 12, 0, 0)
    rows = []
    for month_offset in range(48):
        year = base.year + ((base.month - 1 + month_offset) // 12)
        month = ((base.month - 1 + month_offset) % 12) + 1
        rows.append(
            {
                "created_at": datetime(year, month, 15, 12, 0, 0),
                "classification": "Advanced_Persistent_Threat",
            }
        )
    service = _build_service(rows)
    payload = asyncio.run(service.get_alert_analytics())

    assert payload["trend"]["unit"] == "month"
    assert len(payload["trend"]["points"]) == 12
    assert sum(point["count"] for point in payload["trend"]["points"]) == 48
    assert payload["distribution"][0]["key"] == "advanced_persistent_threat"
