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
