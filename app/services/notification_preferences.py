from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

VALID_SEVERITIES = ("high", "medium", "low")
VALID_FREQUENCIES = ("immediate", "daily")
DEFAULT_TIMEZONE = "Asia/Karachi"
DAILY_DIGEST_HOUR = 9
logger = logging.getLogger(__name__)


def ensure_valid_timezone(timezone_name: str) -> str:
    # Notification timezone is intentionally fixed to Pakistan.
    _ = timezone_name
    return DEFAULT_TIMEZONE


def normalize_severities(values: List[str]) -> List[str]:
    normalized: List[str] = []
    for value in values:
        candidate = str(value).strip().lower()
        if candidate not in VALID_SEVERITIES:
            raise ValueError("severities must contain only high, medium, or low")
        if candidate not in normalized:
            normalized.append(candidate)
    return normalized


def compute_next_digest_at(now_utc: datetime, timezone_name: str) -> datetime:
    aware_now = _ensure_utc(now_utc)
    _ = timezone_name
    try:
        local_tz = ZoneInfo(DEFAULT_TIMEZONE)
    except ZoneInfoNotFoundError:
        logger.warning(
            "Could not resolve '%s'; using UTC for digest scheduling",
            DEFAULT_TIMEZONE,
        )
        local_tz = timezone.utc
    local_now = aware_now.astimezone(local_tz)
    local_target = local_now.replace(hour=DAILY_DIGEST_HOUR, minute=0, second=0, microsecond=0)
    if local_now >= local_target:
        local_target = local_target + timedelta(days=1)
    return local_target.astimezone(timezone.utc).replace(tzinfo=None)


def default_notification_prefs(now_utc: datetime) -> Dict[str, Any]:
    return {
        "email_enabled": False,
        "frequency": "immediate",
        "severities": ["high", "medium", "low"],
        "timezone": DEFAULT_TIMEZONE,
        "cursor_at": now_utc,
        "last_digest_sent_at": None,
        "next_digest_at": None,
    }


def sanitize_stored_notification_prefs(raw: Any, now_utc: datetime) -> Dict[str, Any]:
    if not isinstance(now_utc, datetime):
        now_utc = datetime.utcnow()
    defaults = default_notification_prefs(now_utc)
    if not isinstance(raw, dict):
        return defaults

    email_enabled = bool(raw.get("email_enabled", defaults["email_enabled"]))
    frequency = str(raw.get("frequency", defaults["frequency"])).strip().lower()
    if frequency not in VALID_FREQUENCIES:
        frequency = defaults["frequency"]

    timezone_name = ensure_valid_timezone(str(raw.get("timezone", defaults["timezone"])))

    severities_raw = raw.get("severities")
    severities: List[str]
    if isinstance(severities_raw, list):
        try:
            severities = normalize_severities(severities_raw)
        except ValueError:
            severities = defaults["severities"]
    else:
        severities = defaults["severities"]
    if not severities:
        severities = defaults["severities"]

    cursor_at = _as_naive_utc_datetime(raw.get("cursor_at")) or defaults["cursor_at"]
    last_digest_sent_at = _as_naive_utc_datetime(raw.get("last_digest_sent_at"))
    next_digest_at = _as_naive_utc_datetime(raw.get("next_digest_at"))

    return {
        "email_enabled": email_enabled,
        "frequency": frequency,
        "severities": severities,
        "timezone": timezone_name,
        "cursor_at": cursor_at,
        "last_digest_sent_at": last_digest_sent_at,
        "next_digest_at": next_digest_at,
    }


def _as_naive_utc_datetime(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _ensure_utc(now_utc: datetime) -> datetime:
    if now_utc.tzinfo is None:
        return now_utc.replace(tzinfo=timezone.utc)
    return now_utc.astimezone(timezone.utc)
