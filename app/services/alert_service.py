import re
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from app.core.config import get_settings
from app.db.repositories.log_repository import LogRepository
from app.core.websocket import manager
from app.db.repositories.alert_repository import AlertRepository
from app.services.log_context_service import build_normalized_log_context
from app.services.ml_promotion_service import MLPromotionService
from app.services.ml_suppression_service import MLSuppressionService
from app.services.notification_service import NotificationService
from app.utils.time import coerce_datetime_utc, parse_datetime_utc, utc_now_naive

ANALYTICS_TARGET_BUCKETS = 12
_PLACEHOLDER_LABELS = {"n/a", "na", "none", "null", "undefined", "unknown_attack"}
_NUMERIC_ONLY_RE = re.compile(r"^[+-]?\d+(\.\d+)?$")
ANOMALY_CLASSIFICATION_SENTINEL = "__anomaly__"
MISSING_IP_SENTINEL = "__missing_ip__"
GENERIC_SIGNAL_SENTINEL = "__generic_signal__"
INCIDENT_INACTIVITY_MINUTES = 10


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


def _derive_log_summary(log_doc: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not log_doc:
        return {}
    context = build_normalized_log_context(log_doc)
    return {
        "event_id": str(context.get("event_id") or log_doc.get("_id") or ""),
        "event_time": context.get("event_time") or log_doc.get("timestamp"),
        "source_app": context.get("source_app"),
        "source_ip": context.get("source_ip"),
        "destination_ip": context.get("destination_ip"),
        "channel": context.get("channel"),
        "message": str(context.get("message_normalized") or log_doc.get("message") or "")[:240],
        "event_origin": context.get("event_origin"),
        "decoder_name": context.get("decoder_name"),
        "agent_name": context.get("agent_name"),
        "network": context.get("network"),
    }


def _ensure_utc_naive(value: datetime) -> datetime:
    return coerce_datetime_utc(value)


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
        self._logs = LogRepository()
        self._promotions = MLPromotionService()
        self._suppressions = MLSuppressionService()
        self._notifications = NotificationService(get_settings())

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
        linked_log = await self._logs.get_by_id(log_id)
        metadata_with_summary = dict(metadata or {})
        metadata_with_summary["log_summary"] = _derive_log_summary(linked_log)
        normalized_classification = _normalize_classification(classification)
        correlation_classification = normalized_classification
        if alert_type == "anomaly" and not correlation_classification:
            correlation_classification = ANOMALY_CLASSIFICATION_SENTINEL
        src_ip, dst_ip = self._extract_ips(linked_log)
        signal_key = self._derive_signal_key(linked_log)
        correlation_key = self._build_correlation_key(
            alert_type=alert_type,
            classification=correlation_classification or "",
            source_ip=src_ip,
            destination_ip=dst_ip,
            signal_key=signal_key,
        )
        event_time = utc_now_naive()
        if linked_log:
            raw_time = linked_log.get("event_time") or linked_log.get("timestamp")
            event_time = parse_datetime_utc(raw_time) or event_time
        alert_id, created = await self._alerts.create_or_update_incident(
            correlation_key=correlation_key,
            alert_type=alert_type,
            classification=normalized_classification,
            source_ip=src_ip,
            destination_ip=dst_ip,
            log_id=log_id,
            severity=severity,
            model_version=model_version,
            anomaly_score=anomaly_score,
            metadata=metadata_with_summary,
            event_time=event_time,
            inactivity_minutes=INCIDENT_INACTIVITY_MINUTES,
        )
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

    async def count_alerts(self, filters: Optional[Dict[str, Any]] = None) -> int:
        return await self._alerts.count_alerts(filters=filters)

    async def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return await self._alerts.get_alert(alert_id)

    async def confirm_known_attack(
        self,
        alert_id: str,
        classification: str,
        confirmed_by: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        alert = await self._alerts.get_alert(alert_id)
        if not alert:
            raise ValueError("Alert not found")

        log_id = self._resolve_alert_log_id(alert)
        if not log_id:
            raise ValueError("Linked log is missing for this alert")

        log_doc = await self._logs.get_by_id(log_id)
        if not log_doc:
            raise ValueError("Linked log not found")

        fingerprint = await self._promotions.register_manual_promotion(
            log_doc=log_doc,
            classification=classification,
            created_by=confirmed_by,
            notes=notes,
        )
        normalized = self._promotions.validate_label(
            self._promotions.normalize_classification_label(classification)
        )

        await self._alerts.update_alert_fields(
            alert_id,
            {
                "alert_type": "known_attack",
                "classification": normalized,
                "severity": "high",
                "metadata.feedback": {
                    "verdict": "confirmed_known_attack",
                    "by": confirmed_by,
                    "at": datetime.utcnow(),
                    "notes": notes,
                    "fingerprint": fingerprint,
                },
                "metadata.manual_promotion": {
                    "fingerprint": fingerprint,
                    "classification": normalized,
                    "confirmed_by": confirmed_by,
                    "notes": notes,
                    "confirmed_at": datetime.utcnow(),
                },
            },
        )
        await self._logs.update_fields_by_id(
            log_id,
            {
                "ml_result.alert_type": "known_attack",
                "ml_result.classification": normalized,
                "ml_result.score": 1.0,
                "metadata.feedback": {
                    "verdict": "confirmed_known_attack",
                    "by": confirmed_by,
                    "at": datetime.utcnow(),
                    "notes": notes,
                    "fingerprint": fingerprint,
                },
                "metadata.manual_promotion": {
                    "fingerprint": fingerprint,
                    "classification": normalized,
                    "confirmed_by": confirmed_by,
                    "notes": notes,
                    "confirmed_at": datetime.utcnow(),
                },
            },
        )
        return {
            "alert_id": alert_id,
            "fingerprint": fingerprint,
            "classification": normalized,
        }

    async def mark_false_positive(
        self,
        alert_id: str,
        reviewed_by: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        alert = await self._alerts.get_alert(alert_id)
        if not alert:
            raise ValueError("Alert not found")
        log_id = self._resolve_alert_log_id(alert)
        if not log_id:
            raise ValueError("Linked log is missing for this alert")
        log_doc = await self._logs.get_by_id(log_id)
        if not log_doc:
            raise ValueError("Linked log not found")

        fingerprint = await self._suppressions.mark_false_positive(
            log_doc=log_doc,
            created_by=reviewed_by,
            notes=notes,
        )
        feedback = {
            "verdict": "false_positive",
            "by": reviewed_by,
            "at": datetime.utcnow(),
            "notes": notes,
            "fingerprint": fingerprint,
        }
        await self._alerts.update_alert_fields(
            alert_id,
            {
                "metadata.feedback": feedback,
                "metadata.suppression": {
                    "fingerprint": fingerprint,
                    "active": True,
                    "reason": "false_positive",
                },
            },
        )
        await self._logs.update_fields_by_id(
            log_id,
            {
                "metadata.feedback": feedback,
                "metadata.suppression": {
                    "fingerprint": fingerprint,
                    "active": True,
                    "reason": "false_positive",
                },
            },
        )
        return {
            "alert_id": alert_id,
            "fingerprint": fingerprint,
        }

    @staticmethod
    def _resolve_alert_log_id(alert: Dict[str, Any]) -> str:
        children = alert.get("children")
        if isinstance(children, list) and children:
            latest = children[-1]
            if isinstance(latest, dict):
                value = latest.get("log_id")
                if value:
                    return str(value)
        log_ids = alert.get("log_ids")
        if isinstance(log_ids, list) and log_ids:
            return str(log_ids[-1])
        return str(alert.get("log_id") or "")

    @staticmethod
    def _extract_ips(linked_log: Optional[Dict[str, Any]]) -> tuple[str, str]:
        if not isinstance(linked_log, dict):
            return (MISSING_IP_SENTINEL, MISSING_IP_SENTINEL)
        context = build_normalized_log_context(linked_log)
        src = str(context.get("source_ip") or "").strip() or MISSING_IP_SENTINEL
        dst = str(context.get("destination_ip") or "").strip() or MISSING_IP_SENTINEL
        return (src, dst)

    @staticmethod
    def _build_correlation_key(
        *,
        alert_type: str,
        classification: str,
        source_ip: str,
        destination_ip: str,
        signal_key: str = GENERIC_SIGNAL_SENTINEL,
    ) -> str:
        normalized = [
            str(alert_type or "").strip().lower() or "anomaly",
            str(classification or "").strip().lower() or ANOMALY_CLASSIFICATION_SENTINEL,
            str(source_ip or "").strip().lower() or MISSING_IP_SENTINEL,
            str(destination_ip or "").strip().lower() or MISSING_IP_SENTINEL,
            str(signal_key or "").strip().lower() or GENERIC_SIGNAL_SENTINEL,
        ]
        return "|".join(normalized)

    @staticmethod
    def _derive_signal_key(linked_log: Optional[Dict[str, Any]]) -> str:
        if not isinstance(linked_log, dict):
            return GENERIC_SIGNAL_SENTINEL
        metadata = linked_log.get("metadata") if isinstance(linked_log.get("metadata"), dict) else {}
        raw = metadata.get("raw_wazuh_payload") if isinstance(metadata.get("raw_wazuh_payload"), dict) else {}
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        decoder = raw.get("decoder") if isinstance(raw.get("decoder"), dict) else {}

        rule_id = str(rule.get("id") or "").strip()
        if rule_id:
            return f"rule:{rule_id}"

        decoder_name = str(decoder.get("name") or "").strip().lower()
        if decoder_name:
            return f"decoder:{decoder_name}"

        message = str(linked_log.get("message") or "").strip().lower()
        if message:
            compact = re.sub(r"\s+", " ", message)[:80]
            return f"msg:{compact}"
        return GENERIC_SIGNAL_SENTINEL

    async def get_alert_analytics(self) -> Dict[str, Any]:
        total_alerts = await self._alerts.count_alerts()
        if total_alerts == 0:
            return {
                "severity_counts": {"total": 0, "high": 0, "medium": 0, "low": 0},
                "trend": {"unit": "day", "points": []},
                "distribution": [],
                "total_alerts": 0,
                "first_alert_at": None,
                "last_alert_at": None,
                "window": {"start": None, "end": None, "bucket_unit": "day"},
            }

        distribution_rows = await self._alerts.aggregate_distribution()
        distribution = []
        for row in distribution_rows:
            key = row["key"]
            count = row["count"]
            distribution.append(
                {
                    "key": key,
                    "label": _humanize_label(key),
                    "count": count,
                    "percentage": round((count / total_alerts) * 100, 2) if total_alerts else 0.0,
                }
            )

        span_bounds = await self._alerts.min_max_created_at()
        first_raw = span_bounds.get("min_created_at")
        last_raw = span_bounds.get("max_created_at")
        first_alert_at = _ensure_utc_naive(first_raw) if isinstance(first_raw, datetime) else None
        last_alert_at = _ensure_utc_naive(last_raw) if isinstance(last_raw, datetime) else None

        if not first_alert_at or not last_alert_at:
            severity_counts = await self._alerts.aggregate_severity_counts()
            return {
                "severity_counts": severity_counts,
                "trend": {"unit": "day", "points": []},
                "distribution": distribution,
                "total_alerts": total_alerts,
                "first_alert_at": None,
                "last_alert_at": None,
                "window": {"start": None, "end": None, "bucket_unit": "day"},
            }

        now_utc = datetime.utcnow()
        span_end = max(now_utc, last_alert_at)
        unit = _select_trend_unit(span_end - first_alert_at)
        trend_rows = await self._alerts.aggregate_trend(unit=unit, start=first_alert_at, end=span_end)
        points: list[Dict[str, Any]] = []
        for row in trend_rows:
            bucket_start = row.get("bucket_start")
            if not isinstance(bucket_start, datetime):
                continue
            bucket_start = _ensure_utc_naive(bucket_start)
            bucket_end = _next_bucket_start(bucket_start, unit)
            points.append(
                {
                    "bucket_start": bucket_start,
                    "bucket_end": bucket_end,
                    "label": _format_bucket_label(bucket_start, unit),
                    "count": int(row.get("count") or 0),
                }
            )
        points = _merge_trend_points(points, ANALYTICS_TARGET_BUCKETS) if points else []
        severity_counts = await self._alerts.aggregate_severity_counts()
        return {
            "severity_counts": severity_counts,
            "trend": {"unit": unit, "points": points},
            "distribution": distribution,
            "total_alerts": total_alerts,
            "first_alert_at": first_alert_at,
            "last_alert_at": last_alert_at,
            "window": {"start": first_alert_at, "end": span_end, "bucket_unit": unit},
        }
