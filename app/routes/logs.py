import secrets
import re
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from app.core.config import get_settings
from app.schemas.log import LogCreate, LogResponse
from app.services.auth_service import get_current_user
from app.services.ingestion_service import IngestionService
from app.services.log_context_service import build_normalized_log_context
from app.db.repositories.log_repository import LogRepository
from app.utils.time import as_utc_aware, coerce_datetime_utc

router = APIRouter()

_AUTH_PATTERN = r"(auth|sshd|login|secure)"
_SYSTEM_PATTERN = r"(kern|kernel|syslog|system)"
_CHANNEL_VALUES = {"network", "login", "file", "system", "general"}


def _non_empty_field_filter(field: str) -> Dict[str, Any]:
    return {
        "$and": [
            {field: {"$exists": True}},
            {field: {"$nin": [None, ""]}},
        ]
    }


def _network_presence_filter() -> Dict[str, Any]:
    return {
        "$or": [
            _non_empty_field_filter("metadata.data.srcip"),
            _non_empty_field_filter("metadata.srcip"),
            _non_empty_field_filter("metadata.raw_wazuh_payload.data.srcip"),
            _non_empty_field_filter("metadata.raw_wazuh_payload.srcip"),
            _non_empty_field_filter("metadata.data.dstip"),
            _non_empty_field_filter("metadata.dstip"),
            _non_empty_field_filter("metadata.raw_wazuh_payload.data.dstip"),
            _non_empty_field_filter("metadata.raw_wazuh_payload.dstip"),
        ]
    }


def _decoder_regex_filter(pattern: str) -> Dict[str, Any]:
    regex = {"$regex": pattern, "$options": "i"}
    return {
        "$or": [
            {"metadata.decoder.name": regex},
            {"metadata.raw_wazuh_payload.decoder.name": regex},
        ]
    }


def _source_app_filter_clause(source_app: str) -> Optional[Dict[str, Any]]:
    normalized_source_app = source_app.strip().lower()
    if not normalized_source_app:
        return None

    auth_filter = {
        "$or": [
            {"metadata.location": {"$regex": _AUTH_PATTERN, "$options": "i"}},
            {"metadata.raw_wazuh_payload.location": {"$regex": _AUTH_PATTERN, "$options": "i"}},
            {"source": {"$regex": _AUTH_PATTERN, "$options": "i"}},
        ]
    }
    system_filter = {
        "$or": [
            {"metadata.location": {"$regex": _SYSTEM_PATTERN, "$options": "i"}},
            {"metadata.raw_wazuh_payload.location": {"$regex": _SYSTEM_PATTERN, "$options": "i"}},
            {"source": {"$regex": _SYSTEM_PATTERN, "$options": "i"}},
        ]
    }

    if normalized_source_app == "authentication":
        return auth_filter
    if normalized_source_app == "system":
        return system_filter
    if normalized_source_app == "general system":
        return {"$and": [{"$nor": [auth_filter]}, {"$nor": [system_filter]}]}

    return {
        "$or": [
            {"metadata.location": {"$regex": f"^{re.escape(source_app.strip())}", "$options": "i"}},
            {"metadata.raw_wazuh_payload.location": {"$regex": f"^{re.escape(source_app.strip())}", "$options": "i"}},
            {"source": {"$regex": f"^{re.escape(source_app.strip())}", "$options": "i"}},
        ]
    }


def _channel_filter_clause(channel: str) -> Optional[Dict[str, Any]]:
    normalized_channel = channel.strip().lower()
    if not normalized_channel:
        return None
    if normalized_channel not in _CHANNEL_VALUES:
        return None

    network_filter = _network_presence_filter()
    if normalized_channel == "network":
        return network_filter

    mapped_decoder = {
        "login": "sshd",
        "file": "syscheck",
        "system": "kernel",
    }
    if normalized_channel in mapped_decoder:
        return {
            "$and": [
                {"$nor": [network_filter]},
                _decoder_regex_filter(f"^{mapped_decoder[normalized_channel]}$"),
            ]
        }

    return {
        "$and": [
            {"$nor": [network_filter]},
            {"$nor": [_decoder_regex_filter(r"^(sshd|syscheck|kernel)$")]},
        ]
    }


def _build_log_filters(
    source: Optional[str],
    severity: Optional[str],
    agent: Optional[str],
    origin: Optional[str],
    source_app: Optional[str],
    channel: Optional[str],
    start_ts: Optional[datetime],
    end_ts: Optional[datetime],
) -> dict:
    conditions: list[Dict[str, Any]] = []
    normalized_source = source.strip() if source else ""
    if normalized_source:
        conditions.append({"source": {"$regex": f"^{re.escape(normalized_source)}", "$options": "i"}})
    if severity:
        conditions.append({"severity": severity})

    normalized_agent = agent.strip() if agent else ""
    if normalized_agent:
        regex = {"$regex": f"^{re.escape(normalized_agent)}", "$options": "i"}
        conditions.append(
            {
                "$or": [
                    {"metadata.agent.name": regex},
                    {"metadata.raw_wazuh_payload.agent.name": regex},
                ]
            }
        )

    normalized_origin = origin.strip() if origin else ""
    if normalized_origin:
        regex = {"$regex": f"^{re.escape(normalized_origin)}", "$options": "i"}
        conditions.append(
            {
                "$or": [
                    {"metadata.location": regex},
                    {"metadata.raw_wazuh_payload.location": regex},
                    {"metadata.decoder.name": regex},
                    {"metadata.raw_wazuh_payload.decoder.name": regex},
                    {"source": regex},
                ]
            }
        )

    normalized_source_app = source_app.strip() if source_app else ""
    if normalized_source_app:
        source_app_clause = _source_app_filter_clause(normalized_source_app)
        if source_app_clause:
            conditions.append(source_app_clause)

    normalized_channel = channel.strip() if channel else ""
    if normalized_channel:
        channel_clause = _channel_filter_clause(normalized_channel)
        if channel_clause:
            conditions.append(channel_clause)

    if start_ts or end_ts:
        timestamp_filter: Dict[str, datetime] = {}
        if start_ts:
            timestamp_filter["$gte"] = coerce_datetime_utc(start_ts)
        if end_ts:
            timestamp_filter["$lte"] = coerce_datetime_utc(end_ts)
        conditions.append({"timestamp": timestamp_filter})

    if not conditions:
        return {}
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


def _to_log_response(log: Dict[str, Any]) -> LogResponse:
    context = build_normalized_log_context(log)
    return LogResponse(
        id=str(log["_id"]),
        timestamp=as_utc_aware(log["timestamp"]) or log["timestamp"],
        source=log["source"],
        message=log["message"],
        metadata=log.get("metadata", {}),
        severity=log.get("severity"),
        event_id=context["event_id"],
        event_time=as_utc_aware(context["event_time"]) if context["event_time"] else None,
        agent_name=context["agent_name"],
        event_origin=context["event_origin"],
        decoder_name=context["decoder_name"],
        network=context["network"],
        message_normalized=context["message_normalized"],
        source_app=context["source_app"],
        source_ip=context["source_ip"],
        destination_ip=context["destination_ip"],
        channel=context["channel"],
    )


@router.get("/", response_model=list[LogResponse])
async def list_logs(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    agent: Optional[str] = None,
    origin: Optional[str] = None,
    source_app: Optional[str] = None,
    channel: Optional[str] = None,
    start_ts: Optional[datetime] = None,
    end_ts: Optional[datetime] = None,
) -> list[LogResponse]:
    repo = LogRepository()
    filters = _build_log_filters(
        source=source,
        severity=severity,
        agent=agent,
        origin=origin,
        source_app=source_app,
        channel=channel,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    logs = await repo.list_logs(limit=limit, offset=offset, filters=filters)
    return [_to_log_response(log) for log in logs]


@router.get("/count")
async def count_logs(
    current_user: dict = Depends(get_current_user),
    source: Optional[str] = None,
    severity: Optional[str] = None,
    agent: Optional[str] = None,
    origin: Optional[str] = None,
    source_app: Optional[str] = None,
    channel: Optional[str] = None,
    start_ts: Optional[datetime] = None,
    end_ts: Optional[datetime] = None,
) -> dict[str, int]:
    repo = LogRepository()
    filters = _build_log_filters(
        source=source,
        severity=severity,
        agent=agent,
        origin=origin,
        source_app=source_app,
        channel=channel,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    total = await repo.count_logs(filters=filters)
    return {"total": total}


@router.get("/{log_id}", response_model=LogResponse)
async def get_log(
    log_id: str,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    repo = LogRepository()
    log = await repo.get_by_id(log_id)
    if not log:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log not found")
    return _to_log_response(log)


@router.post("/", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def ingest_log(
    payload: LogCreate,
    current_user: dict = Depends(get_current_user),
) -> LogResponse:
    service = IngestionService()
    log_id = await service.ingest_log(payload.dict(), source="api")
    payload_dict = payload.dict()
    context = build_normalized_log_context(payload_dict)
    return LogResponse(id=log_id, **payload_dict, **context)


@router.post("/wazuh", response_model=LogResponse, status_code=status.HTTP_201_CREATED)
async def ingest_wazuh_log(
    payload: dict,
    x_wazuh_key: Optional[str] = Header(default=None, alias="X-WAZUH-KEY"),
) -> LogResponse:
    settings = get_settings()
    configured_key = settings.wazuh_ingest_key
    if not configured_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Wazuh ingestion key is not configured",
        )
    if not x_wazuh_key or not secrets.compare_digest(x_wazuh_key, configured_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Wazuh ingest key")

    rule = payload.get("rule", {}) if isinstance(payload.get("rule"), dict) else {}
    agent = payload.get("agent", {}) if isinstance(payload.get("agent"), dict) else {}
    decoder = payload.get("decoder", {}) if isinstance(payload.get("decoder"), dict) else {}
    level = int(rule.get("level", 0) or 0)
    severity = "high" if level >= 12 else "medium" if level >= 7 else "low"
    message = (
        str(rule.get("description"))
        if rule.get("description")
        else str(payload.get("full_log") or decoder.get("name") or "wazuh alert")
    )
    timestamp = payload.get("timestamp") or datetime.utcnow()
    normalized_payload = {
        "timestamp": timestamp,
        "source": str(agent.get("name") or "wazuh"),
        "message": message,
        "severity": severity,
        "metadata": payload,
    }

    service = IngestionService()
    log_id = await service.ingest_log(normalized_payload, source="wazuh")
    repo = LogRepository()
    created = await repo.get_by_id(log_id)
    if not created:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to persist Wazuh log")
    return _to_log_response(created)
