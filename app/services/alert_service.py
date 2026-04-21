import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.core.config import get_settings
from app.core.websocket import manager
from app.db.repositories.alert_repository import AlertRepository
from app.services.notification_service import NotificationService

ANALYTICS_TARGET_BUCKETS = 12
_PLACEHOLDER_LABELS = {"n/a", "na", "none", "null", "undefined"}
_NUMERIC_ONLY_RE = re.compile(r"^[+-]?\d+(\.\d+)?$")


def _normalize_classification(classification: Optional[str]) -> Optional[str]:
    if isinstance(classification, str):
        normalized = classification.strip()
        if normalized:
            return normalized
    return None


def _clean_value(value: Any) -> str:
    text = str(value or "").strip()
    return text


def _canonical_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return normalized or "uncategorized"


def _humanize_label(value: str) -> str:
    if value == "uncategorized":
        return "Uncategorized"
    return " ".join(part.capitalize() for part in value.split("_") if part)


def _resolve_distribution_key(alert: Dict[str, Any]) -> str:
    candidates = [
        alert.get("classification"),
        alert.get("alert_type"),
        alert.get("attack_type"),
        alert.get("type"),
    ]
    for candidate in candidates:
        raw = _clean_value(candidate)
        if not raw:
            continue
        if raw.lower() in _PLACEHOLDER_LABELS:
            continue
        if _NUMERIC_ONLY_RE.match(raw):
            continue
        return _canonical_key(raw)
    return "uncategorized"


def _ensure_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _select_trend_unit(span: timedelta) -> str:
    if span <= timedelta(days=2):
        return "hour"
    if span <= timedelta(days=180):
        return "day"
    if span <= timedelta(days=730):
        return "week"
    return "month"


def _truncate_bucket(value: datetime, unit: str) -> datetime:
    if unit == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    if unit == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "week":
        day = value.replace(hour=0, minute=0, second=0, microsecond=0)
        return day - timedelta(days=day.weekday())
    if unit == "month":
        return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"Unsupported trend unit: {unit}")


def _next_bucket_start(value: datetime, unit: str) -> datetime:
    if unit == "hour":
        return value + timedelta(hours=1)
    if unit == "day":
        return value + timedelta(days=1)
    if unit == "week":
        return value + timedelta(days=7)
    if unit == "month":
        year = value.year + (1 if value.month == 12 else 0)
        month = 1 if value.month == 12 else value.month + 1
        return value.replace(year=year, month=month, day=1)
    raise ValueError(f"Unsupported trend unit: {unit}")


def _format_bucket_label(value: datetime, unit: str) -> str:
    if unit == "hour":
        return value.strftime("%Y-%m-%d %H:00")
    if unit == "day":
        return value.strftime("%Y-%m-%d")
    if unit == "week":
        return f"Week of {value.strftime('%Y-%m-%d')}"
    if unit == "month":
        return value.strftime("%Y-%m")
    raise ValueError(f"Unsupported trend unit: {unit}")


def _merge_trend_points(points: list[Dict[str, Any]], target: int) -> list[Dict[str, Any]]:
    total_points = len(points)
    if total_points <= target:
        return points

    base = total_points // target
    remainder = total_points % target
    merged: list[Dict[str, Any]] = []
    index = 0
    for group_idx in range(target):
        group_size = base + (1 if group_idx < remainder else 0)
        group = points[index:index + group_size]
        index += group_size
        merged.append(
            {
                "bucket_start": group[0]["bucket_start"],
                "bucket_end": group[-1]["bucket_end"],
                "label": group[0]["label"],
                "count": sum(item["count"] for item in group),
            }
        )
    return merged


class AlertService:
    def __init__(self) -> None:
        self._alerts = AlertRepository()
        self._notifications = NotificationService(get_settings())

    async def create_alert(
        self,
        log_id: str,
        alert_type: str,
        severity: str,
        model_version: str,
        metadata: Dict[str, Any],
        classification: Optional[str] = None,
        anomaly_score: Optional[float] = None,
    ) -> str:
        # Alerts are derived artifacts and are never updated after creation.
        payload = {
            "created_at": datetime.utcnow(),
            "log_id": log_id,
            "alert_type": alert_type,
            "severity": severity,
            "classification": _normalize_classification(classification),
            "anomaly_score": anomaly_score,
            "model_version": model_version,
            "metadata": metadata,
        }
        alert_id = await self._alerts.create_alert(payload)
        await manager.broadcast({"event": "alert_created", "alert_id": alert_id, "severity": severity})
        alert = await self._alerts.get_alert(alert_id)
        if alert:
            await self._notifications.send_immediate_for_alert(alert)
        return alert_id

    async def create_or_get_alert(
        self,
        log_id: str,
        alert_type: str,
        severity: str,
        model_version: str,
        metadata: Dict[str, Any],
        classification: Optional[str] = None,
        anomaly_score: Optional[float] = None,
    ) -> str:
        payload = {
            "created_at": datetime.utcnow(),
            "log_id": log_id,
            "alert_type": alert_type,
            "severity": severity,
            "classification": _normalize_classification(classification),
            "anomaly_score": anomaly_score,
            "model_version": model_version,
            "metadata": metadata,
        }
        alert_id, created = await self._alerts.create_or_get_alert(payload)
        if created:
            await manager.broadcast({"event": "alert_created", "alert_id": alert_id, "severity": severity})
            alert = await self._alerts.get_alert(alert_id)
            if alert:
                await self._notifications.send_immediate_for_alert(alert)
        return alert_id

    async def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> list:
        return await self._alerts.list_alerts(limit=limit, offset=offset, filters=filters)

    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return await self._alerts.get_alert(alert_id)

    async def get_alert_analytics(self) -> Dict[str, Any]:
        alert_rows = await self._alerts.list_alerts_for_analytics()
        total_alerts = len(alert_rows)
        if total_alerts == 0:
            return {
                "trend": {"unit": "day", "points": []},
                "distribution": [],
                "total_alerts": 0,
                "first_alert_at": None,
                "last_alert_at": None,
            }

        distribution_counts: Dict[str, int] = {}
        created_at_values: list[datetime] = []
        for row in alert_rows:
            key = _resolve_distribution_key(row)
            distribution_counts[key] = distribution_counts.get(key, 0) + 1

            created_at = row.get("created_at")
            if isinstance(created_at, datetime):
                created_at_values.append(_ensure_utc_naive(created_at))

        distribution = []
        for key, count in sorted(
            distribution_counts.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            distribution.append(
                {
                    "key": key,
                    "label": _humanize_label(key),
                    "count": count,
                    "percentage": round((count / total_alerts) * 100, 2) if total_alerts else 0.0,
                }
            )

        if not created_at_values:
            return {
                "trend": {"unit": "day", "points": []},
                "distribution": distribution,
                "total_alerts": total_alerts,
                "first_alert_at": None,
                "last_alert_at": None,
            }

        first_alert_at = min(created_at_values)
        last_alert_at = max(created_at_values)
        now_utc = datetime.utcnow()
        span_end = max(now_utc, last_alert_at)
        unit = _select_trend_unit(span_end - first_alert_at)

        bucket_counts: Dict[datetime, int] = {}
        for created_at in created_at_values:
            bucket_start = _truncate_bucket(created_at, unit)
            bucket_counts[bucket_start] = bucket_counts.get(bucket_start, 0) + 1

        points: list[Dict[str, Any]] = []
        cursor = _truncate_bucket(first_alert_at, unit)
        end_bucket = _truncate_bucket(span_end, unit)
        while cursor <= end_bucket:
            next_start = _next_bucket_start(cursor, unit)
            points.append(
                {
                    "bucket_start": cursor,
                    "bucket_end": next_start,
                    "label": _format_bucket_label(cursor, unit),
                    "count": bucket_counts.get(cursor, 0),
                }
            )
            cursor = next_start

        points = _merge_trend_points(points, ANALYTICS_TARGET_BUCKETS)
        return {
            "trend": {"unit": unit, "points": points},
            "distribution": distribution,
            "total_alerts": total_alerts,
            "first_alert_at": first_alert_at,
            "last_alert_at": last_alert_at,
        }
