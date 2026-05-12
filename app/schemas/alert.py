from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: str
    incident_id: str
    created_at: datetime
    opened_at: datetime
    last_seen_at: datetime
    closed_at: Optional[datetime] = None
    status: str
    event_count: int
    log_ids: list[str]
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    classification: Optional[str] = None
    model_versions_seen: list[str]
    metadata: Dict[str, Any]
    children: list[Dict[str, Any]] = []


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


class AlertSeverityCountsResponse(BaseModel):
    total: int
    high: int
    medium: int
    low: int


class AlertAnalyticsWindowResponse(BaseModel):
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    bucket_unit: str


class AlertAnalyticsResponse(BaseModel):
    severity_counts: AlertSeverityCountsResponse
    trend: AlertTrendResponse
    distribution: list[AlertDistributionPointResponse]
    total_alerts: int
    first_alert_at: Optional[datetime] = None
    last_alert_at: Optional[datetime] = None
    window: AlertAnalyticsWindowResponse


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
