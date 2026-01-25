from fastapi import APIRouter, Depends, HTTPException, status

from app.schemas.log import LogCreate, LogResponse
from app.services.auth_service import get_current_user
from app.services.ingestion_service import IngestionService
from app.db.repositories.log_repository import LogRepository

router = APIRouter()


@router.get("/", response_model=list[LogResponse])
async def list_logs(
    current_user: dict = Depends(get_current_user),
    limit: int = 50,
) -> list[LogResponse]:
    repo = LogRepository()
    logs = await repo.list_logs(limit=limit)
    response = []
    for log in logs:
        response.append(
            LogResponse(
                id=str(log["_id"]),
                timestamp=log["timestamp"],
                source=log["source"],
                message=log["message"],
                metadata=log.get("metadata", {}),
                severity=log.get("severity"),
            )
        )
    return response


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(
    log_id: str,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    repo = LogRepository()
    log = await repo.get_by_id(log_id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log not found")
    return LogResponse(
        id=str(log["_id"]),
        timestamp=log["timestamp"],
        source=log["source"],
        message=log["message"],
        metadata=log.get("metadata", {}),
        severity=log.get("severity"),
    )


@router.post("/", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    payload: LogCreate,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    service = IngestionService()
    log_id = await service.ingest_log(payload.dict(), source="api")
    return LogResponse(id=log_id, **payload.dict())
