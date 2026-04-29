import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.config import get_settings
from app.schemas.ml import (
    BatchInferenceRequest,
    ModelVersionActivateRequest,
    RetrainJobCreateRequest,
    RetrainJobResponse,
    SuppressionActionResponse,
    SuppressionEntryResponse,
)
from app.services.auth_service import get_current_admin_user, get_current_user
from app.services.ml_model_ops_service import MLModelOpsService
from app.services.ml_service import MLService
from app.services.ml_suppression_service import MLSuppressionService

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


@router.post("/models/retrain", response_model=RetrainJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_retrain_job(
    payload: RetrainJobCreateRequest,
    current_user: dict = Depends(get_current_admin_user),
) -> RetrainJobResponse:
    service = MLModelOpsService(get_settings())
    try:
        job_id = await service.create_retrain_job(
            reason=payload.reason,
            requested_by=current_user["email"],
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    job = await service.get_retrain_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create retrain job")
    return RetrainJobResponse(**job)


@router.get("/models/retrain-jobs", response_model=list[RetrainJobResponse])
async def list_retrain_jobs(
    current_user: dict = Depends(get_current_admin_user),
    limit: int = Query(20, ge=1, le=100),
) -> list[RetrainJobResponse]:
    service = MLModelOpsService(get_settings())
    jobs = await service.list_retrain_jobs(limit=limit)
    return [RetrainJobResponse(**item) for item in jobs]


@router.get("/models/retrain-jobs/{job_id}", response_model=RetrainJobResponse)
async def get_retrain_job(
    job_id: str,
    current_user: dict = Depends(get_current_admin_user),
) -> RetrainJobResponse:
    service = MLModelOpsService(get_settings())
    job = await service.get_retrain_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Retrain job not found")
    return RetrainJobResponse(**job)


@router.get("/models/versions")
async def list_model_versions(
    current_user: dict = Depends(get_current_admin_user),
) -> dict:
    service = MLModelOpsService(get_settings())
    try:
        versions = await service.list_versions()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return {"versions": versions}


@router.post("/models/rollback")
async def rollback_model(
    payload: ModelVersionActivateRequest,
    current_user: dict = Depends(get_current_admin_user),
) -> dict:
    service = MLModelOpsService(get_settings())
    try:
        result = await service.rollback(payload.target_version)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return result


@router.get("/suppressions", response_model=list[SuppressionEntryResponse])
async def list_suppressions(
    current_user: dict = Depends(get_current_admin_user),
    limit: int = Query(200, ge=1, le=500),
) -> list[SuppressionEntryResponse]:
    service = MLSuppressionService()
    rows = await service.list_suppressions(limit=limit)
    return [SuppressionEntryResponse(**row) for row in rows]


@router.post("/suppressions/{fingerprint}/deactivate", response_model=SuppressionActionResponse)
async def deactivate_suppression(
    fingerprint: str,
    current_user: dict = Depends(get_current_admin_user),
) -> SuppressionActionResponse:
    service = MLSuppressionService()
    try:
        await service.deactivate(fingerprint)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return SuppressionActionResponse(fingerprint=fingerprint, active=False)


@router.post("/suppressions/{fingerprint}/activate", response_model=SuppressionActionResponse)
async def activate_suppression(
    fingerprint: str,
    current_user: dict = Depends(get_current_admin_user),
) -> SuppressionActionResponse:
    service = MLSuppressionService()
    try:
        await service.activate(fingerprint)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return SuppressionActionResponse(fingerprint=fingerprint, active=True)
