from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Optional

from app.utils.time import parse_datetime_utc

AUTH_SOURCE_PATTERN = re.compile(r"(auth|sshd|login|secure)", re.IGNORECASE)
SYSTEM_SOURCE_PATTERN = re.compile(r"(kern|kernel|syslog|system)", re.IGNORECASE)
LOGIN_DECODER = "sshd"
FILE_DECODER = "syscheck"
SYSTEM_DECODER = "kernel"


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
    return parse_datetime_utc(value)


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


def _top_level_network_context(log_doc: Dict[str, Any]) -> Optional[Dict[str, Optional[str]]]:
    network = _as_dict(log_doc.get("network"))
    srcip = _first_non_empty(network.get("srcip"), log_doc.get("source_ip"))
    dstip = _first_non_empty(network.get("dstip"), log_doc.get("destination_ip"))
    srcport = _first_non_empty(network.get("srcport"))
    dstport = _first_non_empty(network.get("dstport"))
    protocol = _first_non_empty(network.get("protocol"))
    action = _first_non_empty(network.get("action"))

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


def _derive_source_value(payload: Dict[str, Any], log_doc: Dict[str, Any]) -> Optional[str]:
    data = _as_dict(payload.get("data"))
    network = _as_dict(log_doc.get("network"))
    return _first_non_empty(
        data.get("srcip"),
        payload.get("srcip"),
        data.get("srcuser"),
        network.get("srcip"),
        log_doc.get("source_ip"),
    )


def _derive_destination_value(payload: Dict[str, Any], log_doc: Dict[str, Any]) -> Optional[str]:
    data = _as_dict(payload.get("data"))
    network_doc = _as_dict(log_doc.get("network"))
    dst = _first_non_empty(
        data.get("dstip"),
        payload.get("dstip"),
        network_doc.get("dstip"),
        log_doc.get("destination_ip"),
        data.get("dstuser"),
        data.get("hostname"),
    )
    if dst:
        return dst

    network = extract_network_context(payload)
    if network:
        return _first_non_empty(network.get("dstip"), network.get("dstuser"))
    return None


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
    network = extract_network_context(payload) or _top_level_network_context(log_doc)
    source_app = classify_source_app(payload, log_doc)
    source_ip = _derive_source_value(payload, log_doc)
    destination_ip = _derive_destination_value(payload, log_doc)
    channel = classify_channel(network, decoder_name)

    return {
        "event_id": _first_non_empty(payload.get("id"), log_doc.get("event_id")),
        "event_time": event_time,
        "agent_name": _as_str(agent.get("name")),
        "event_origin": event_origin,
        "decoder_name": decoder_name,
        "network": network,
        "message_normalized": message_normalized,
        "source_app": source_app,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "channel": channel,
    }


def classify_source_app(payload: Dict[str, Any], log_doc: Dict[str, Any]) -> str:
    source_parts = [
        _as_str(payload.get("location")),
        _as_str(log_doc.get("source")),
    ]
    source_text = " ".join(part for part in source_parts if part).lower()
    if AUTH_SOURCE_PATTERN.search(source_text):
        return "Authentication"
    if SYSTEM_SOURCE_PATTERN.search(source_text):
        return "System"
    return "General System"


def classify_channel(
    network: Optional[Dict[str, Optional[str]]],
    decoder_name: Optional[str],
) -> str:
    if network and (_as_str(network.get("srcip")) or _as_str(network.get("dstip"))):
        return "Network"

    normalized_decoder = str(decoder_name or "").strip().lower()
    if normalized_decoder == LOGIN_DECODER:
        return "Login"
    if normalized_decoder == FILE_DECODER:
        return "File"
    if normalized_decoder == SYSTEM_DECODER:
        return "System"
    return "General"
