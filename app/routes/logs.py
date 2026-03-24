import secrets
import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.core.config import get_settings
from app.schemas.log import LogCreate, LogResponse
from app.services.auth_service import get_current_user
from app.services.ingestion_service import IngestionService
from app.db.repositories.log_repository import LogRepository

router = APIRouter()


def _build_log_filters(
    source: Optional[str],
    severity: Optional[str],
    start_ts: Optional[datetime],
    end_ts: Optional[datetime],
) -> dict:
    filters: dict = {}
    normalized_source = source.strip() if source else ""
    if normalized_source:
        filters["source"] = {"$regex": f"^{re.escape(normalized_source)}", "$options": "i"}
    if severity:
        filters["severity"] = severity
    if start_ts or end_ts:
        filters["timestamp"] = {}
        if start_ts:
            filters["timestamp"]["$gte"] = start_ts
        if end_ts:
            filters["timestamp"]["$lte"] = end_ts
    return filters


@router.get("/", response_model=list[LogResponse])
async def list_logs(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    start_ts: Optional[datetime] = None,
    end_ts: Optional[datetime] = None,
) -> list[LogResponse]:
    repo = LogRepository()
    filters = _build_log_filters(source=source, severity=severity, start_ts=start_ts, end_ts=end_ts)
    logs = await repo.list_logs(limit=limit, offset=offset, filters=filters)
    response = []
    for log in logs:
        response.append(
            LogResponse(
                id=str(log["_id"]),
                timestamp=log["timestamp"],
                source=log["source"],
                message=log["message"],
                metadata=log.get("metadata", {}),
                severity=log.get("severity"),
            )
        )
    return response


@router.get("/count")
async def count_logs(
    current_user: dict = Depends(get_current_user),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    start_ts: Optional[datetime] = None,
    end_ts: Optional[datetime] = None,
) -> dict[str, int]:
    repo = LogRepository()
    filters = _build_log_filters(source=source, severity=severity, start_ts=start_ts, end_ts=end_ts)
    total = await repo.count_logs(filters=filters)
    return {"total": total}


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(
    log_id: str,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    repo = LogRepository()
    log = await repo.get_by_id(log_id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log not found")
    return LogResponse(
        id=str(log["_id"]),
        timestamp=log["timestamp"],
        source=log["source"],
        message=log["message"],
        metadata=log.get("metadata", {}),
        severity=log.get("severity"),
    )


@router.post("/", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    payload: LogCreate,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    service = IngestionService()
    log_id = await service.ingest_log(payload.dict(), source="api")
    return LogResponse(id=log_id, **payload.dict())


@router.post("/wazuh", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def ingest_wazuh_log(
    payload: dict,
    x_wazuh_key: Optional[str] = Header(default=None, alias="X-WAZUH-KEY"),
) -> LogResponse:
    settings = get_settings()
    configured_key = settings.wazuh_ingest_key
    if not configured_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Wazuh ingestion key is not configured",
        )
    if not x_wazuh_key or not secrets.compare_digest(x_wazuh_key, configured_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Wazuh ingest key")

    rule = payload.get("rule", {}) if isinstance(payload.get("rule"), dict) else {}
    agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
    decoder = payload.get("decoder", {}) if isinstance(payload.get("decoder"), dict) else {}
    level = int(rule.get("level", 0) or 0)
    severity = "high" if level >= 12 else "medium" if level >= 7 else "low"
    message = (
        str(rule.get("description"))
        if rule.get("description")
        else str(payload.get("full_log") or decoder.get("name") or "wazuh alert")
    )
    timestamp = payload.get("timestamp") or datetime.utcnow()
    normalized_payload = {
        "timestamp": timestamp,
        "source": str(agent.get("name") or "wazuh"),
        "message": message,
        "severity": severity,
        "metadata": payload,
    }

    service = IngestionService()
    log_id = await service.ingest_log(normalized_payload, source="wazuh")
    repo = LogRepository()
    created = await repo.get_by_id(log_id)
    if not created:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist Wazuh log")
    return LogResponse(
        id=str(created["_id"]),
        timestamp=created["timestamp"],
        source=created["source"],
        message=created["message"],
        metadata=created.get("metadata", {}),
        severity=created.get("severity"),
    )
