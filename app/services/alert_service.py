from datetime import datetime
from typing import Any, Dict, Optional

from app.core.websocket import manager
from app.db.repositories.alert_repository import AlertRepository


class AlertService:
    def __init__(self) -> None:
        self._alerts = AlertRepository()

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
            "classification": classification,
            "anomaly_score": anomaly_score,
            "model_version": model_version,
            "metadata": metadata,
        }
        alert_id = await self._alerts.create_alert(payload)
        await manager.broadcast({"event": "alert_created", "alert_id": alert_id, "severity": severity})
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
