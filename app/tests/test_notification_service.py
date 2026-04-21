import asyncio
from datetime import datetime
from types import SimpleNamespace

import app.services.notification_service as notification_service_module
from app.services.notification_service import NotificationService


class _FakeUserRepository:
    def __init__(self):
        self.immediate_users = []
        self.digest_users = []
        self.updated_digest_calls = []

    async def list_immediate_notification_users(self, severity, alert_created_at, limit=200):
        self.last_immediate_args = (severity, alert_created_at, limit)
        return self.immediate_users

    async def list_due_daily_digest_users(self, now_utc, limit=200):
        self.last_digest_args = (now_utc, limit)
        return self.digest_users

    async def update_digest_schedule(self, user_id, next_digest_at, last_digest_sent_at=None):
        self.updated_digest_calls.append((user_id, next_digest_at, last_digest_sent_at))


class _FakeAlertRepository:
    def __init__(self):
        self.alerts = []
        self.last_digest_query = None

    async def list_alerts_for_digest(self, severities, start_ts, end_ts, limit=500):
        self.last_digest_query = (severities, start_ts, end_ts, limit)
        return self.alerts


def test_send_immediate_for_alert_sends_email_for_matching_users(monkeypatch):
    sent = []

    def _fake_send_email(_settings, to_email, subject, body):
        sent.append((to_email, subject, body))

    monkeypatch.setattr(notification_service_module, "send_email", _fake_send_email)

    users = _FakeUserRepository()
    users.immediate_users = [{"email": "analyst@example.com"}]
    alerts = _FakeAlertRepository()
    service = NotificationService(SimpleNamespace(frontend_base_url="http://localhost:3000"), users, alerts)

    asyncio.run(
        service.send_immediate_for_alert(
            {
                "_id": "alert-1",
                "created_at": datetime(2026, 4, 21, 5, 0, 0),
                "severity": "high",
                "alert_type": "known_attack",
                "classification": "SSH_BRUTE",
                "anomaly_score": 0.9,
            }
        )
    )

    assert len(sent) == 1
    assert sent[0][0] == "analyst@example.com"
    assert "alert-1" in sent[0][2]


def test_process_due_digests_sends_and_advances_schedule(monkeypatch):
    sent = []

    def _fake_send_email(_settings, to_email, subject, body):
        sent.append((to_email, subject, body))

    monkeypatch.setattr(notification_service_module, "send_email", _fake_send_email)

    users = _FakeUserRepository()
    users.digest_users = [
        {
            "_id": "u1",
            "email": "analyst@example.com",
            "notification_prefs": {
                "email_enabled": True,
                "frequency": "daily",
                "severities": ["high"],
                "timezone": "Asia/Karachi",
                "cursor_at": datetime(2026, 4, 20, 0, 0, 0),
                "last_digest_sent_at": None,
                "next_digest_at": datetime(2026, 4, 21, 4, 0, 0),
            },
        }
    ]
    alerts = _FakeAlertRepository()
    alerts.alerts = [
        {
            "_id": "a1",
            "created_at": datetime(2026, 4, 21, 4, 30, 0),
            "severity": "high",
            "alert_type": "known_attack",
            "classification": "SSH_BRUTE",
            "anomaly_score": 0.99,
        }
    ]
    service = NotificationService(SimpleNamespace(frontend_base_url="http://localhost:3000"), users, alerts)

    now_utc = datetime(2026, 4, 21, 5, 0, 0)
    asyncio.run(service.process_due_digests(now_utc))

    assert len(sent) == 1
    assert len(users.updated_digest_calls) == 1
    assert users.updated_digest_calls[0][0] == "u1"
    assert users.updated_digest_calls[0][2] == now_utc


def test_process_due_digests_rolls_next_schedule_without_email_when_no_alerts(monkeypatch):
    sent = []

    def _fake_send_email(_settings, to_email, subject, body):
        sent.append((to_email, subject, body))

    monkeypatch.setattr(notification_service_module, "send_email", _fake_send_email)

    users = _FakeUserRepository()
    users.digest_users = [
        {
            "_id": "u2",
            "email": "analyst@example.com",
            "notification_prefs": {
                "email_enabled": True,
                "frequency": "daily",
                "severities": ["high"],
                "timezone": "Asia/Karachi",
                "cursor_at": datetime(2026, 4, 20, 0, 0, 0),
                "last_digest_sent_at": None,
                "next_digest_at": datetime(2026, 4, 21, 4, 0, 0),
            },
        }
    ]
    alerts = _FakeAlertRepository()
    service = NotificationService(SimpleNamespace(frontend_base_url="http://localhost:3000"), users, alerts)

    asyncio.run(service.process_due_digests(datetime(2026, 4, 21, 5, 0, 0)))

    assert sent == []
    assert len(users.updated_digest_calls) == 1
    assert users.updated_digest_calls[0][2] is None
