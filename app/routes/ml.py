import asyncio

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.config import get_settings
from app.schemas.ml import BatchInferenceRequest, RollbackRequest, TrainingDataRequest
from app.services.auth_service import get_current_user
from app.services.ml_service import MLService

router = APIRouter()
_batch_infer_state_lock = asyncio.Lock()
_batch_infer_in_progress = False


@router.post("/batch-infer", status_code=status.HTTP_200_OK)
async def batch_infer(
    payload: BatchInferenceRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    global _batch_infer_in_progress

    async with _batch_infer_state_lock:
        if _batch_infer_in_progress:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="batch inference already running",
            )
        _batch_infer_in_progress = True

    try:
        service = MLService(get_settings())
        return await service.run_batch_inference(payload.batch_size)
    finally:
        async with _batch_infer_state_lock:
            _batch_infer_in_progress = False


@router.post("/retrain", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def retrain_models(
    _payload: TrainingDataRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Retraining is disabled in cloud-only mode. Retrain models in the cloud-model service workflow.",
    )


@router.post("/rollback", status_code=status.HTTP_501_NOT_IMPLEMENTED)
async def rollback_models(
    _payload: RollbackRequest,
    current_user: dict = Depends(get_current_user),
) -> dict:
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Rollback is disabled in cloud-only mode.",
    )
