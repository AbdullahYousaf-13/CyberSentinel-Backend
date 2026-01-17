import numpy as np
from fastapi import APIRouter, Depends, status

from app.core.config import get_settings
from app.schemas.ml import BatchInferenceRequest, RollbackRequest, TrainingDataRequest
from app.services.auth_service import get_current_user
from app.services.ml_service import MLService

router = APIRouter()


@router.post("/batch-infer", status_code=status.HTTP_200_OK)
async def batch_infer(
    payload: BatchInferenceRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    service = MLService(get_settings())
    return await service.run_batch_inference(payload.batch_size)


@router.post("/retrain", status_code=status.HTTP_200_OK)
async def retrain_models(
    payload: TrainingDataRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    service = MLService(get_settings())
    features = np.array(payload.features, dtype=float)
    labels = np.array(payload.labels)
    version = service.retrain_models(features, labels, payload.reason)
    return {"version": version}


@router.post("/rollback", status_code=status.HTTP_200_OK)
async def rollback_models(
    payload: RollbackRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    service = MLService(get_settings())
    service.rollback(payload.target_version)
    return {"active_version": payload.target_version}
