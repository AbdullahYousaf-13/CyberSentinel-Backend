import asyncio
from datetime import datetime, timedelta

from app.services.alert_service import (
    AlertService,
    _derive_log_summary,
    _merge_trend_points,
    _normalize_classification,
    _resolve_distribution_key,
    _select_trend_unit,
)


class _FakeAlertRepository:
    def __init__(self, rows):
        self._rows = rows

    async def count_alerts(self):
        return len(self._rows)

    async def aggregate_distribution(self):
        counts = {}
        for row in self._rows:
            key = _resolve_distribution_key(row)
            counts[key] = counts.get(key, 0) + 1
        return [{"key": key, "count": count} for key, count in counts.items()]

    async def min_max_created_at(self):
        created = [row.get("created_at") for row in self._rows if isinstance(row.get("created_at"), datetime)]
        if not created:
            return {"min_created_at": None, "max_created_at": None}
        return {"min_created_at": min(created), "max_created_at": max(created)}

    async def aggregate_trend(self, unit, start, end):
        buckets = {}
        for row in self._rows:
            dt = row.get("created_at")
            if not isinstance(dt, datetime):
                continue
            if unit == "hour":
                key_dt = dt.replace(minute=0, second=0, microsecond=0)
            elif unit == "day":
                key_dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
            elif unit == "week":
                day = dt.replace(hour=0, minute=0, second=0, microsecond=0)
                key_dt = day - timedelta(days=day.weekday())
            else:
                key_dt = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            buckets[key_dt] = buckets.get(key_dt, 0) + 1
        return [
            {"bucket_start": bucket_start, "count": count, "label": str(bucket_start)}
            for bucket_start, count in sorted(buckets.items(), key=lambda item: item[0])
        ]

    async def aggregate_severity_counts(self):
        counts = {"total": 0, "high": 0, "medium": 0, "low": 0}
        for row in self._rows:
            counts["total"] += 1
            severity = str(row.get("severity") or "").lower()
            if severity in {"high", "critical"}:
                counts["high"] += 1
            elif severity == "medium":
                counts["medium"] += 1
            else:
                counts["low"] += 1
        return counts


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


def test_derive_log_summary_extracts_stable_fields() -> None:
    log_doc = {
        "_id": "id1",
        "event_id": "ev-1",
        "timestamp": datetime(2026, 1, 1, 10, 0, 0),
        "source_app": "System",
        "network": {"srcip": "1.1.1.1", "dstip": "2.2.2.2"},
        "message": "hello",
    }
    summary = _derive_log_summary(log_doc)
    assert summary["event_id"] == "ev-1"
    assert summary["source_ip"] == "1.1.1.1"
    assert summary["destination_ip"] == "2.2.2.2"
    assert summary["message"] == "hello"


def test_get_alert_analytics_returns_empty_payload_for_no_alerts() -> None:
    service = _build_service([])
    payload = asyncio.run(service.get_alert_analytics())

    assert payload["total_alerts"] == 0
    assert payload["severity_counts"] == {"total": 0, "high": 0, "medium": 0, "low": 0}
    assert payload["trend"]["points"] == []
    assert payload["distribution"] == []
    assert payload["first_alert_at"] is None
    assert payload["last_alert_at"] is None


def test_get_alert_analytics_short_span_uses_hour_buckets() -> None:
    now = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    rows = [
        {"created_at": now - timedelta(hours=20), "classification": "SSH_BRUTE", "severity": "high"},
        {"created_at": now - timedelta(hours=5), "alert_type": "credential_attack", "severity": "medium"},
        {"created_at": now - timedelta(hours=1), "classification": "N/A", "alert_type": "new_signal", "severity": "low"},
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
    assert payload["severity_counts"] == {"total": 3, "high": 1, "medium": 1, "low": 1}


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
                "severity": "critical",
            }
        )
    service = _build_service(rows)
    payload = asyncio.run(service.get_alert_analytics())

    assert payload["trend"]["unit"] == "month"
    assert len(payload["trend"]["points"]) == 12
    assert sum(point["count"] for point in payload["trend"]["points"]) == 48
    assert payload["distribution"][0]["key"] == "advanced_persistent_threat"
