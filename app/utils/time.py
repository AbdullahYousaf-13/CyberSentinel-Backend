import re
from datetime import datetime, timezone
from typing import Any, Optional

_COMPACT_OFFSET_RE = re.compile(r"[+-]\d{4}$")


def utc_now_naive() -> datetime:
    return datetime.utcnow()


def ensure_utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def parse_datetime_utc(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return ensure_utc_naive(value)

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 10_000_000_000:
            ts = ts / 1000.0
        return datetime.utcfromtimestamp(ts)

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        iso = raw.replace("Z", "+00:00")
        if _COMPACT_OFFSET_RE.search(iso):
            iso = f"{iso[:-5]}{iso[-5:-2]}:{iso[-2:]}"
        try:
            parsed = datetime.fromisoformat(iso)
        except ValueError:
            return None
        return ensure_utc_naive(parsed)

    return None


def coerce_datetime_utc(value: Any, fallback: Optional[datetime] = None) -> datetime:
    parsed = parse_datetime_utc(value)
    if parsed is not None:
        return parsed
    if fallback is not None:
        return ensure_utc_naive(fallback)
    return utc_now_naive()


def as_utc_aware(value: Any) -> Optional[datetime]:
    parsed = parse_datetime_utc(value)
    if parsed is None:
        return None
    return parsed.replace(tzinfo=timezone.utc)
