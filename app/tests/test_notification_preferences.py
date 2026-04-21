from datetime import datetime

from app.services.notification_preferences import (
    compute_next_digest_at,
    ensure_valid_timezone,
    normalize_severities,
)


def test_compute_next_digest_at_uses_timezone_9am_local() -> None:
    # 2026-04-21 01:00 UTC == 06:00 Asia/Karachi.
    now_utc = datetime(2026, 4, 21, 1, 0, 0)
    next_digest = compute_next_digest_at(now_utc, "Asia/Karachi")
    # Next 09:00 Asia/Karachi should be 04:00 UTC same day.
    assert next_digest == datetime(2026, 4, 21, 4, 0, 0)


def test_compute_next_digest_at_rolls_to_next_day_after_9am_local() -> None:
    # 2026-04-21 07:00 UTC == 12:00 Asia/Karachi.
    now_utc = datetime(2026, 4, 21, 7, 0, 0)
    next_digest = compute_next_digest_at(now_utc, "Asia/Karachi")
    # Next 09:00 local should be next day 04:00 UTC.
    assert next_digest == datetime(2026, 4, 22, 4, 0, 0)


def test_normalize_severities_dedupes_and_lowercases() -> None:
    assert normalize_severities(["HIGH", "medium", "high"]) == ["high", "medium"]


def test_ensure_valid_timezone_is_always_pakistan() -> None:
    assert ensure_valid_timezone("Mars/Olympus") == "Asia/Karachi"
