import logging
from typing import Any, Dict

import httpx
from fastapi import HTTPException, status

from app.core.config import Settings
from app.db.repositories.agent_audit_repository import AgentAuditRepository

logger = logging.getLogger(__name__)


class InvestigationAgentService:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._audit = AgentAuditRepository()

    async def request_plan(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self._settings.agent_service_url:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Agent service not configured")
        url = f"{self._settings.agent_service_url.rstrip('/')}/plan"
        try:
            await self._audit.record_event({"event": "request", "payload": payload})
            async with httpx.AsyncClient(timeout=self._settings.agent_timeout_seconds) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                await self._audit.record_event({"event": "response", "payload": data, "alert_id": payload.get("alert_id")})
                return data
        except httpx.HTTPError as exc:
            logger.exception("Agent service call failed: %s", exc)
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Agent service error") from exc
