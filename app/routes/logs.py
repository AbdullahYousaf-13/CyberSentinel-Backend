from fastapi import APIRouter, Depends, status

from app.schemas.log import LogCreate, LogResponse
from app.services.auth_service import get_current_user
from app.services.ingestion_service import IngestionService

router = APIRouter()


@router.post("/", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    payload: LogCreate,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    service = IngestionService()
    log_id = await service.ingest_log(payload.dict(), source="api")
    return LogResponse(id=log_id, **payload.dict())
