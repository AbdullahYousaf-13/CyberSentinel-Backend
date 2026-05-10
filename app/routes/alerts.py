from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

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


def _response_classification(alert: dict) -> Optional[str]:
    raw = alert.get("classification")
    if isinstance(raw, str) and raw.strip():
        value = raw.strip()
        if value.upper() == "UNKNOWN_ATTACK":
            return None
        return value
    return None


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    start_ts: Optional[datetime] = None,
    end_ts: Optional[datetime] = None,
) -> list[AlertResponse]:
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
    alerts = await service.list_alerts(limit=limit, offset=offset, filters=filters)
    response = []
    for alert in alerts:
        response.append(
            AlertResponse(
                id=str(alert["_id"]),
                created_at=alert["created_at"],
                log_id=alert["log_id"],
                alert_type=alert["alert_type"],
                severity=alert["severity"],
                classification=_response_classification(alert),
                anomaly_score=alert.get("anomaly_score"),
                model_version=alert["model_version"],
                metadata=alert.get("metadata", {}),
            )
        )
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
    return AlertResponse(
        id=str(alert["_id"]),
        created_at=alert["created_at"],
        log_id=alert["log_id"],
        alert_type=alert["alert_type"],
        severity=alert["severity"],
        classification=_response_classification(alert),
        anomaly_score=alert.get("anomaly_score"),
        model_version=alert["model_version"],
        metadata=alert.get("metadata", {}),
    )


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
