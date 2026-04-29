from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class BatchInferenceRequest(BaseModel):
    batch_size: int = Field(100, ge=1, le=1000)


class RetrainRequest(BaseModel):
    reason: str


class TrainingDataRequest(BaseModel):
    reason: str
    features: list[list[float]]
    labels: list[int]


class RollbackRequest(BaseModel):
    target_version: str


class RetrainJobCreateRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=300)


class RetrainJobResponse(BaseModel):
    id: str
    status: str
    reason: str
    requested_by: str
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class ModelVersionActivateRequest(BaseModel):
    target_version: str = Field(..., min_length=1, max_length=64)


class SuppressionActionRequest(BaseModel):
    fingerprint: str = Field(..., min_length=10, max_length=128)


class SuppressionEntryResponse(BaseModel):
    fingerprint: str
    active: bool
    reason: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    notes: str | None = None


class SuppressionActionResponse(BaseModel):
    fingerprint: str
    active: bool
