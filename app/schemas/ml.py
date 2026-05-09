from datetime import datetime
from typing import Any, Literal

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
    model_family: str = Field("web_access", min_length=2, max_length=64)
    dataset_mode: Literal["feedback_only", "bootstrap_seed", "bootstrap_plus_feedback"] = "feedback_only"


class RetrainJobResponse(BaseModel):
    id: str
    status: str
    reason: str
    requested_by: str
    model_family: str | None = None
    dataset_mode: str | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class BackfillJobCreateRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=300)
    model_family: str = Field("web_access", min_length=2, max_length=64)
    scan_limit: int = Field(20000, ge=1, le=50000)


class BackfillJobResponse(BaseModel):
    id: str
    status: str
    reason: str
    requested_by: str
    model_family: str | None = None
    scan_limit: int | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
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


class BootstrapPreviewRequest(BaseModel):
    model_family: str = Field("web_access", min_length=2, max_length=64)
    scan_limit: int = Field(5000, ge=1, le=20000)
    preview_limit: int = Field(100, ge=0, le=1000)
    include_feedback_overrides: bool = True
    min_class_support: int = Field(10, ge=1, le=500)


class BootstrapPreviewThresholdsResponse(BaseModel):
    benign_required: int
    attack_required: int
    benign_available: int
    attack_available: int
    passed: bool


class BootstrapPreviewRowResponse(BaseModel):
    log_id: str
    timestamp: str
    decoder_name: str
    message: str
    heuristic_verdict: str
    heuristic_classification: str | None = None
    heuristic_reason: str | None = None
    review_verdict: str
    review_classification: str | None = None
    label_source: str


class BootstrapPreviewResponse(BaseModel):
    model_family: str
    feature_schema_version: str
    scanned_logs: int
    usable_samples: int
    skipped_logs: int
    feedback_override_count: int
    label_distribution: dict[str, int] = Field(default_factory=dict)
    raw_label_distribution: dict[str, int] = Field(default_factory=dict)
    verdict_distribution: dict[str, int] = Field(default_factory=dict)
    thresholds: BootstrapPreviewThresholdsResponse
    rows: list[BootstrapPreviewRowResponse] = Field(default_factory=list)


class BootstrapReviewImportItem(BaseModel):
    log_id: str = Field(..., min_length=1, max_length=64)
    review_verdict: Literal["skip", "confirmed_benign", "false_positive", "confirmed_known_attack"]
    review_classification: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, max_length=500)


class BootstrapReviewImportRequest(BaseModel):
    model_family: str = Field("web_access", min_length=2, max_length=64)
    items: list[BootstrapReviewImportItem] = Field(default_factory=list)


class BootstrapReviewImportErrorResponse(BaseModel):
    log_id: str
    error: str


class BootstrapReviewImportResponse(BaseModel):
    model_family: str
    applied: int
    skipped: int
    failed: int
    errors: list[BootstrapReviewImportErrorResponse] = Field(default_factory=list)
