from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.agent import InvestigationPlanResponse
from app.schemas.alert import AlertResponse
from app.services.alert_service import AlertService
from app.services.auth_service import get_current_user
from app.services.investigation_agent_service import InvestigationAgentService
from app.core.config import get_settings

router = APIRouter()


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    current_user: dict = Depends(get_current_user),
) -> list[AlertResponse]:
    service = AlertService()
    alerts = await service.list_alerts()
    response = []
    for alert in alerts:
        response.append(
            AlertResponse(
                id=str(alert["_id"]),
                created_at=alert["created_at"],
                log_id=alert["log_id"],
                alert_type=alert["alert_type"],
                severity=alert["severity"],
                classification=alert.get("classification"),
                anomaly_score=alert.get("anomaly_score"),
                model_version=alert["model_version"],
                metadata=alert.get("metadata", {}),
            )
        )
    return response


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
        classification=alert.get("classification"),
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
