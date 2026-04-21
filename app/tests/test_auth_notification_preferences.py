import asyncio
from datetime import datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services.auth_service import AuthService


class _FakeUserRepository:
    def __init__(self, user_doc):
        self.user_doc = user_doc
        self.updated = None

    async def get_by_email(self, _email):
        return self.user_doc

    async def update_notification_preferences(self, user_id, prefs):
        self.updated = (user_id, prefs)


def _service_with_user(user_doc):
    service = AuthService.__new__(AuthService)
    service._settings = SimpleNamespace(frontend_base_url="http://localhost:3000")
    service._users = _FakeUserRepository(user_doc)
    return service


def test_update_notification_preferences_blocks_unverified_enable() -> None:
    service = _service_with_user({"_id": "u1", "email_verified": False, "notification_prefs": {}})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            service.update_notification_preferences(
                email="a@example.com",
                email_enabled=True,
                frequency="immediate",
                severities=["high"],
                timezone_name="UTC",
            )
        )
    assert exc.value.status_code == 400


def test_update_notification_preferences_rejects_empty_severity_when_enabled() -> None:
    service = _service_with_user({"_id": "u1", "email_verified": True, "notification_prefs": {}})
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            service.update_notification_preferences(
                email="a@example.com",
                email_enabled=True,
                frequency="immediate",
                severities=[],
                timezone_name="UTC",
            )
        )
    assert exc.value.status_code == 422


def test_update_notification_preferences_ignores_invalid_timezone_input() -> None:
    service = _service_with_user({"_id": "u1", "email_verified": True, "notification_prefs": {}})
    result = asyncio.run(
        service.update_notification_preferences(
            email="a@example.com",
            email_enabled=True,
            frequency="daily",
            severities=["high"],
            timezone_name="Invalid/Zone",
        )
    )
    assert result["timezone"] == "Asia/Karachi"


def test_update_notification_preferences_sets_next_digest_for_daily() -> None:
    service = _service_with_user({"_id": "u1", "email_verified": True, "notification_prefs": {}})
    result = asyncio.run(
        service.update_notification_preferences(
            email="a@example.com",
            email_enabled=True,
            frequency="daily",
            severities=["high", "medium"],
            timezone_name="Asia/Karachi",
        )
    )
    assert result["email_enabled"] is True
    assert result["frequency"] == "daily"
    assert result["severities"] == ["high", "medium"]
    assert isinstance(result["cursor_at"], datetime)
    assert isinstance(result["next_digest_at"], datetime)
    assert service._users.updated is not None
