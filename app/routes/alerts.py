from datetime import datetime
import logging
import re
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder

from app.schemas.agent import InvestigationPlanResponse
from app.schemas.alert import (
    AlertAnalyticsResponse,
    AlertResponse,
    ConfirmKnownAttackRequest,
    ConfirmKnownAttackResponse,
    MarkFalsePositiveRequest,
    MarkFalsePositiveResponse,
)
from app.services.alert_service import AlertService
from app.services.auth_service import get_current_admin_user, get_current_user
from app.services.investigation_agent_service import InvestigationAgentService
from app.core.config import get_settings

router = APIRouter()
logger = logging.getLogger(__name__)
LIST_CHILDREN_PREVIEW_LIMIT = 10
LIST_LOG_IDS_PREVIEW_LIMIT = 25


def _response_classification(alert: dict) -> Optional[str]:
    raw = alert.get("classification")
    if isinstance(raw, str) and raw.strip():
        value = raw.strip()
        if value.upper() == "UNKNOWN_ATTACK":
            return None
        return value
    return None


def _map_alert_response(alert: dict) -> AlertResponse:
    created_at = alert.get("created_at")
    if not isinstance(created_at, datetime):
        created_at = datetime.utcnow()
    children_raw = alert.get("children")
    children: list[dict[str, Any]] = []
    if isinstance(children_raw, list):
        for child in children_raw:
            if not isinstance(child, dict):
                continue
            normalized_child = jsonable_encoder(child)
            if "log_id" in normalized_child:
                normalized_child["log_id"] = str(normalized_child.get("log_id") or "")
            children.append(normalized_child)
    log_ids_raw = alert.get("log_ids")
    log_ids = [str(item) for item in log_ids_raw] if isinstance(log_ids_raw, list) else []
    if not log_ids and alert.get("log_id"):
        log_ids = [str(alert.get("log_id"))]
    metadata_raw = alert.get("metadata", {})
    if not isinstance(metadata_raw, dict):
        metadata_raw = {}
    metadata = jsonable_encoder(metadata_raw)
    return AlertResponse(
        id=str(alert["_id"]),
        incident_id=str(alert.get("incident_id") or alert["_id"]),
        created_at=created_at,
        opened_at=alert.get("opened_at") or created_at,
        last_seen_at=alert.get("last_seen_at") or created_at,
        closed_at=alert.get("closed_at"),
        status=str(alert.get("status") or "open"),
        event_count=int(alert.get("event_count") or len(log_ids) or len(children) or 0),
        log_ids=log_ids,
        alert_type=str(alert.get("alert_type") or "anomaly"),
        severity=str(alert.get("severity") or "low"),
        source_ip=str(alert.get("source_ip") or ""),
        destination_ip=str(alert.get("destination_ip") or ""),
        classification=_response_classification(alert),
        model_versions_seen=[str(item) for item in (alert.get("model_versions_seen") or [])],
        metadata=metadata,
        children=children,
    )


def _build_alert_search_filter(query: str) -> dict[str, Any]:
    escaped_query = re.escape(query.strip())
    regex = {"$regex": escaped_query, "$options": "i"}
    return {
        "$or": [
            {"incident_id": regex},
            {"alert_type": regex},
            {"severity": regex},
            {"status": regex},
            {"classification": regex},
            {"source_ip": regex},
            {"destination_ip": regex},
            {"log_ids": regex},
            {"model_versions_seen": regex},
            {"metadata.log_summary.event_id": regex},
            {"metadata.log_summary.agent_name": regex},
            {"metadata.log_summary.decoder_name": regex},
            {"metadata.log_summary.event_origin": regex},
            {"metadata.log_summary.message": regex},
            {"children.log_id": regex},
            {"children.severity": regex},
            {"children.model_version": regex},
            {"children.metadata.log_summary.event_id": regex},
            {"children.metadata.log_summary.agent_name": regex},
            {"children.metadata.log_summary.decoder_name": regex},
            {"children.metadata.log_summary.event_origin": regex},
            {"children.metadata.log_summary.message": regex},
        ]
    }


@router.get("/")
async def list_alerts(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    start_ts: Optional[datetime] = None,
    end_ts: Optional[datetime] = None,
    q: Optional[str] = None,
) -> list[dict]:
    service = AlertService()
    filters = {}
    if severity:
        if severity.lower() == "high":
            filters["severity"] = {"$in": ["high", "critical"]}
        else:
            filters["severity"] = severity
    if alert_type:
        filters["alert_type"] = alert_type
    if start_ts or end_ts:
        filters["created_at"] = {}
        if start_ts:
            filters["created_at"]["$gte"] = start_ts
        if end_ts:
            filters["created_at"]["$lte"] = end_ts
    if q and q.strip():
        filters["$and"] = [_build_alert_search_filter(q)]
    try:
        alerts = await service.list_alerts(limit=limit, offset=offset, filters=filters)
    except Exception:  # noqa: BLE001
        logger.exception("Failed to list alerts from repository")
        return []

    response: list[dict] = []
    for alert in alerts:
        try:
            row = jsonable_encoder(_map_alert_response(alert))
            children = row.get("children") if isinstance(row.get("children"), list) else []
            preview: list[dict] = []
            for item in children[-LIST_CHILDREN_PREVIEW_LIMIT:]:
                if not isinstance(item, dict):
                    continue
                meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                summary = meta.get("log_summary") if isinstance(meta.get("log_summary"), dict) else {}
                preview.append(
                    {
                        "log_id": item.get("log_id"),
                        "event_time": item.get("event_time"),
                        "severity": item.get("severity"),
                        "model_version": item.get("model_version"),
                        "anomaly_score": item.get("anomaly_score"),
                        "message": str(summary.get("message") or "")[:180],
                    }
                )
            row["children"] = preview
            log_ids = row.get("log_ids") if isinstance(row.get("log_ids"), list) else []
            row["log_ids"] = log_ids[-LIST_LOG_IDS_PREVIEW_LIMIT:]
            response.append(row)
        except Exception:  # noqa: BLE001
            alert_id = str(alert.get("_id")) if isinstance(alert, dict) else "<unknown>"
            logger.exception("Skipping malformed alert document: %s", alert_id)
            continue
    return response


@router.get("/analytics", response_model=AlertAnalyticsResponse)
async def get_alert_analytics(
    current_user: dict = Depends(get_current_user),
) -> AlertAnalyticsResponse:
    service = AlertService()
    analytics = await service.get_alert_analytics()
    return AlertAnalyticsResponse(**analytics)


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
) -> AlertResponse:
    service = AlertService()
    alert = await service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return _map_alert_response(alert)


@router.post("/{alert_id}/investigation-plan", response_model=InvestigationPlanResponse)
async def get_investigation_plan(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
) -> InvestigationPlanResponse:
    alert_service = AlertService()
    alert = await alert_service.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    settings = get_settings()
    agent_service = InvestigationAgentService(settings)
    payload = {
        "alert_id": alert_id,
        "alert_type": alert["alert_type"],
        "severity": alert["severity"],
        "classification": alert.get("classification"),
        "metadata": alert.get("metadata", {}),
    }
    plan = await agent_service.request_plan(payload)
    return InvestigationPlanResponse(**plan)


@router.post("/{alert_id}/confirm-known", response_model=ConfirmKnownAttackResponse)
async def confirm_known_attack(
    alert_id: str,
    payload: ConfirmKnownAttackRequest,
    current_user: dict = Depends(get_current_admin_user),
) -> ConfirmKnownAttackResponse:
    service = AlertService()
    try:
        result = await service.confirm_known_attack(
            alert_id=alert_id,
            classification=payload.classification,
            confirmed_by=current_user["email"],
            notes=payload.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ConfirmKnownAttackResponse(**result)


@router.post("/{alert_id}/mark-false-positive", response_model=MarkFalsePositiveResponse)
async def mark_false_positive(
    alert_id: str,
    payload: MarkFalsePositiveRequest,
    current_user: dict = Depends(get_current_admin_user),
) -> MarkFalsePositiveResponse:
    service = AlertService()
    try:
        result = await service.mark_false_positive(
            alert_id=alert_id,
            reviewed_by=current_user["email"],
            notes=payload.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return MarkFalsePositiveResponse(**result)
