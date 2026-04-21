from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _first_non_empty(*values: Any) -> Optional[str]:
    for value in values:
        text = _as_str(value)
        if text:
            return text
    return None


def _parse_event_time(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 10_000_000_000:
            ts = ts / 1000.0
        return datetime.utcfromtimestamp(ts)

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        iso = raw.replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", iso):
            iso = f"{iso[:-5]}{iso[-5:-2]}:{iso[-2:]}"
        try:
            parsed = datetime.fromisoformat(iso)
            if parsed.tzinfo is None:
                return parsed
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            return None
    return None


def get_raw_wazuh_payload(log_doc: Dict[str, Any]) -> Dict[str, Any]:
    metadata = _as_dict(log_doc.get("metadata"))
    raw_payload = _as_dict(metadata.get("raw_wazuh_payload"))
    if raw_payload:
        return raw_payload
    return metadata


def extract_network_context(payload: Dict[str, Any]) -> Optional[Dict[str, Optional[str]]]:
    data = _as_dict(payload.get("data"))
    srcip = _first_non_empty(data.get("srcip"), payload.get("srcip"))
    dstip = _first_non_empty(data.get("dstip"), payload.get("dstip"))
    srcport = _first_non_empty(data.get("srcport"), payload.get("srcport"))
    dstport = _first_non_empty(data.get("dstport"), payload.get("dstport"))
    protocol = _first_non_empty(data.get("protocol"), payload.get("protocol"))
    action = _first_non_empty(data.get("action"), payload.get("action"), data.get("status"), payload.get("status"))

    if not any([srcip, dstip, srcport, dstport, protocol, action]):
        return None

    return {
        "srcip": srcip,
        "dstip": dstip,
        "srcport": srcport,
        "dstport": dstport,
        "protocol": protocol,
        "action": action,
    }


def build_normalized_log_context(log_doc: Dict[str, Any]) -> Dict[str, Any]:
    payload = get_raw_wazuh_payload(log_doc)
    decoder = _as_dict(payload.get("decoder"))
    agent = _as_dict(payload.get("agent"))

    message_normalized = _first_non_empty(
        _as_dict(payload.get("rule")).get("description"),
        payload.get("full_log"),
        log_doc.get("message"),
        decoder.get("name"),
    )

    event_time = _parse_event_time(payload.get("timestamp")) or _parse_event_time(log_doc.get("timestamp"))
    decoder_name = _as_str(decoder.get("name"))
    event_origin = _first_non_empty(payload.get("location"), decoder_name, log_doc.get("source"))

    return {
        "event_id": _as_str(payload.get("id")),
        "event_time": event_time,
        "agent_name": _as_str(agent.get("name")),
        "event_origin": event_origin,
        "decoder_name": decoder_name,
        "network": extract_network_context(payload),
        "message_normalized": message_normalized,
    }
