from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from app.core.config import Settings
from app.core.email import send_email
from app.db.repositories.alert_repository import AlertRepository
from app.db.repositories.user_repository import UserRepository
from app.services.notification_preferences import (
    compute_next_digest_at,
    sanitize_stored_notification_prefs,
)

logger = logging.getLogger(__name__)

_DIGEST_IDLE_SLEEP_SEC = 30.0
_digest_task: Optional[asyncio.Task] = None
_digest_stop_event: Optional[asyncio.Event] = None


class NotificationService:
    def __init__(
        self,
        settings: Settings,
        user_repo: Optional[UserRepository] = None,
        alert_repo: Optional[AlertRepository] = None,
    ) -> None:
        self._settings = settings
        self._users = user_repo or UserRepository()
        self._alerts = alert_repo or AlertRepository()

    async def send_immediate_for_alert(self, alert_doc: Dict[str, Any]) -> None:
        created_at = alert_doc.get("created_at")
        if not isinstance(created_at, datetime):
            created_at = datetime.utcnow()
        severity = str(alert_doc.get("severity") or "").strip().lower()
        if not severity:
            return

        recipients = await self._users.list_immediate_notification_users(
            severity=severity,
            alert_created_at=created_at,
        )
        if not recipients:
            return

        alert_id = str(alert_doc.get("_id") or "unknown")
        subject = f"[CyberSentinel] Immediate alert: {severity.upper()} {alert_doc.get('alert_type', 'alert')}"
        body = self._build_single_alert_email_body(alert_id=alert_id, alert=alert_doc)
        for user in recipients:
            try:
                send_email(self._settings, user["email"], subject, body)
            except Exception:  # noqa: BLE001
                logger.exception("Failed immediate alert email for user %s", user.get("email"))

    async def process_due_digests(self, now_utc: Optional[datetime] = None) -> None:
        run_at = now_utc or datetime.utcnow()
        users = await self._users.list_due_daily_digest_users(run_at)
        for user in users:
            user_id = str(user["_id"])
            prefs = sanitize_stored_notification_prefs(user.get("notification_prefs"), run_at)
            since = prefs["cursor_at"]
            last_sent = prefs.get("last_digest_sent_at")
            if isinstance(last_sent, datetime) and last_sent > since:
                since = last_sent

            alerts = await self._alerts.list_alerts_for_digest(
                severities=prefs["severities"],
                start_ts=since,
                end_ts=run_at,
            )
            sent = False
            if alerts:
                subject = f"[CyberSentinel] Daily digest ({len(alerts)} alerts)"
                body = self._build_digest_email_body(alerts=alerts, start_ts=since, end_ts=run_at)
                try:
                    send_email(self._settings, user["email"], subject, body)
                    sent = True
                except Exception:  # noqa: BLE001
                    logger.exception("Failed daily digest email for user %s", user.get("email"))

            next_digest_at = compute_next_digest_at(run_at, prefs["timezone"])
            await self._users.update_digest_schedule(
                user_id=user_id,
                next_digest_at=next_digest_at,
                last_digest_sent_at=run_at if sent else None,
            )

    def _build_single_alert_email_body(self, alert_id: str, alert: Dict[str, Any]) -> str:
        dashboard_url = f"{self._settings.frontend_base_url.rstrip('/')}/alerts"
        created_at = alert.get("created_at")
        created_at_text = created_at.isoformat() if isinstance(created_at, datetime) else "N/A"
        lines = [
            "CyberSentinel detected a new alert that matches your notification preferences.",
            "",
            f"Alert ID: {alert_id}",
            f"Severity: {str(alert.get('severity') or '').upper() or 'N/A'}",
            f"Alert Type: {alert.get('alert_type') or 'N/A'}",
            f"Classification: {alert.get('classification') or 'N/A'}",
            f"Score: {alert.get('anomaly_score') if alert.get('anomaly_score') is not None else 'N/A'}",
            f"Timestamp (UTC): {created_at_text}",
            "",
            f"Review alerts: {dashboard_url}",
        ]
        return "\n".join(lines)

    def _build_digest_email_body(self, alerts: list[Dict[str, Any]], start_ts: datetime, end_ts: datetime) -> str:
        dashboard_url = f"{self._settings.frontend_base_url.rstrip('/')}/alerts"
        lines = [
            "CyberSentinel daily alert digest",
            "",
            f"Window start (UTC): {start_ts.isoformat()}",
            f"Window end (UTC): {end_ts.isoformat()}",
            f"Matching alerts: {len(alerts)}",
            "",
        ]
        for alert in alerts:
            alert_id = str(alert.get("_id") or "unknown")
            created_at = alert.get("created_at")
            created_at_text = created_at.isoformat() if isinstance(created_at, datetime) else "N/A"
            lines.extend(
                [
                    f"- [{alert_id}] severity={str(alert.get('severity') or '').upper() or 'N/A'} "
                    f"type={alert.get('alert_type') or 'N/A'} "
                    f"classification={alert.get('classification') or 'N/A'} "
                    f"score={alert.get('anomaly_score') if alert.get('anomaly_score') is not None else 'N/A'} "
                    f"timestamp={created_at_text}",
                ]
            )

        lines.extend(
            [
                "",
                f"Review alerts: {dashboard_url}",
            ]
        )
        return "\n".join(lines)


async def start_notification_digest_worker(settings: Settings) -> None:
    global _digest_task, _digest_stop_event
    if _digest_task and not _digest_task.done():
        return

    _digest_stop_event = asyncio.Event()
    service = NotificationService(settings)

    async def _runner() -> None:
        assert _digest_stop_event is not None
        while not _digest_stop_event.is_set():
            try:
                await service.process_due_digests()
            except Exception:  # noqa: BLE001
                logger.exception("Notification digest worker failure")
            await asyncio.sleep(_DIGEST_IDLE_SLEEP_SEC)

    _digest_task = asyncio.create_task(_runner(), name="notification-digest-worker")
    logger.info("Notification digest worker started")


async def stop_notification_digest_worker() -> None:
    global _digest_task, _digest_stop_event
    if _digest_stop_event:
        _digest_stop_event.set()
    if _digest_task:
        try:
            await asyncio.wait_for(_digest_task, timeout=5.0)
        except asyncio.TimeoutError:
            _digest_task.cancel()
            try:
                await _digest_task
            except asyncio.CancelledError:
                pass
    _digest_task = None
    _digest_stop_event = None
