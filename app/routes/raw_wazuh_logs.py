import secrets
import json
from typing import Any, List, Optional

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.services.raw_wazuh_pipeline_service import RawWazuhPipelineService

router = APIRouter()

_MAX_LOGS = 500
_MAX_PAYLOAD_BYTES = 1024 * 1024


class RawWazuhIngestBody(BaseModel):
    source: str
    type: str
    logs: List[Any]
    sentAt: int


@router.post("/raw_wazuh_logs", status_code=status.HTTP_201_CREATED)
async def ingest_raw_wazuh_logs(
    body: RawWazuhIngestBody,
    x_ingestion_key: Optional[str] = Header(default=None, alias="x-ingestion-key"),
) -> dict[str, int]:
    if body.source != "wazuh" or body.type != "raw":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='payload must include source="wazuh" and type="raw"',
        )

    if len(body.logs) > _MAX_LOGS:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"logs must contain at most {_MAX_LOGS} entries",
        )
    payload_size = len(
        json.dumps(
            {"source": body.source, "type": body.type, "logs": body.logs, "sentAt": body.sentAt},
            separators=(",", ":"),
        ).encode("utf-8")
    )
    if payload_size > _MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"payload must be <= {_MAX_PAYLOAD_BYTES} bytes",
        )

    settings = get_settings()
    configured = settings.wazuh_ingest_key
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Wazuh ingestion key is not configured",
        )
    if not x_ingestion_key or not secrets.compare_digest(x_ingestion_key, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ingestion key")

    pipeline = RawWazuhPipelineService(settings)
    return await pipeline.ingest_batch(body.logs, body.sentAt)
