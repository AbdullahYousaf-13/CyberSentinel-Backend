from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class AlertLogContextResponse(BaseModel):
    event_id: Optional[str] = None
    event_time: Optional[datetime] = None
    agent_name: Optional[str] = None
    event_origin: Optional[str] = None
    decoder_name: Optional[str] = None
    network: Optional[Dict[str, Optional[str]]] = None
    message_normalized: Optional[str] = None
    source_app: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    channel: Optional[str] = None


class AlertResponse(BaseModel):
    id: str
    created_at: datetime
    log_id: str
    alert_type: str
    severity: str
    classification: Optional[str] = None
    anomaly_score: Optional[float] = None
    model_version: str
    metadata: Dict[str, Any]
    log_context: Optional[AlertLogContextResponse] = None


class AlertTrendPointResponse(BaseModel):
    bucket_start: datetime
    bucket_end: datetime
    label: str
    count: int


class AlertTrendResponse(BaseModel):
    unit: str
    points: list[AlertTrendPointResponse]


class AlertDistributionPointResponse(BaseModel):
    key: str
    label: str
    count: int
    percentage: float


class AlertAnalyticsResponse(BaseModel):
    trend: AlertTrendResponse
    distribution: list[AlertDistributionPointResponse]
    total_alerts: int
    severity_counts: Dict[str, int] = Field(
        default_factory=lambda: {"high": 0, "medium": 0, "low": 0}
    )
    first_alert_at: Optional[datetime] = None
    last_alert_at: Optional[datetime] = None


class ConfirmKnownAttackRequest(BaseModel):
    classification: str
    notes: Optional[str] = None


class ConfirmKnownAttackResponse(BaseModel):
    alert_id: str
    fingerprint: str
    classification: str


class MarkFalsePositiveRequest(BaseModel):
    notes: Optional[str] = None


class MarkFalsePositiveResponse(BaseModel):
    alert_id: str
    fingerprint: str
