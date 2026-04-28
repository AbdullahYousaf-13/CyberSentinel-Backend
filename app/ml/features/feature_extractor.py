import logging
import re
from typing import Any, Dict, List

import numpy as np

logger = logging.getLogger(__name__)


class FeatureExtractor:
    CICIDS_2017_FEATURES: List[str] = [
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",
        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Length",
        "Bwd Header Length",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Min Packet Length",
        "Max Packet Length",
        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",
        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",
        "URG Flag Count",
        "CWE Flag Count",
        "ECE Flag Count",
        "Down/Up Ratio",
        "Average Packet Size",
        "Avg Fwd Segment Size",
        "Avg Bwd Segment Size",
        "Fwd Header Length.1",
        "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk",
        "Fwd Avg Bulk Rate",
        "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk",
        "Bwd Avg Bulk Rate",
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
        "Init_Win_bytes_forward",
        "Init_Win_bytes_backward",
        "act_data_pkt_fwd",
        "min_seg_size_forward",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]

    KEY_ALIASES: Dict[str, List[str]] = {
        "destinationport": ["dstport", "dport", "destination_port", "destport", "port"],
        "flowduration": ["duration", "flow_duration"],
        "totalfwdpackets": ["fwdpacketcount", "total_forward_packets"],
        "totalbackwardpackets": ["bwdpacketcount", "total_backward_packets"],
        "flowbytess": ["flowbytespersecond", "bytes_per_second", "flow_bytes_sec"],
        "flowpacketss": ["flowpacketspersecond", "packets_per_second", "flow_packets_sec"],
        "fwdheaderlength1": ["fwdheaderlength_1", "fwd_header_length_1"],
        "init_win_bytes_forward": ["initwinbytesforward", "init_window_bytes_forward"],
        "init_win_bytes_backward": ["initwinbytesbackward", "init_window_bytes_backward"],
    }

    def __init__(self) -> None:
        self._severity_map = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}

    def transform(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        if not logs:
            return np.zeros((0, len(self.CICIDS_2017_FEATURES)), dtype=float)

        features: List[List[float]] = []
        for log in logs:
            metadata = log.get("metadata", {}) or {}
            if not isinstance(metadata, dict):
                metadata = {}

            lookup = self._build_lookup(log, metadata)
            feature_vector = [self._extract_feature_value(feature_name, lookup) for feature_name in self.CICIDS_2017_FEATURES]
            features.append(feature_vector)
        return np.array(features, dtype=float)

    @staticmethod
    def _normalize_key(key: str) -> str:
        return "".join(ch for ch in str(key).lower() if ch.isalnum())

    def _build_lookup(self, log: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        combined: Dict[str, Any] = {}
        combined.update(metadata)
        self._merge_raw_wazuh_payload(combined, metadata)
        for key, value in log.items():
            if key in {"metadata", "message"}:
                continue
            combined[key] = value
        self._derive_http_proxy_features(combined, log)

        normalized: Dict[str, Any] = {}
        for key, value in combined.items():
            for variant in self._key_variants(str(key)):
                normalized.setdefault(variant, value)
        return normalized

    @staticmethod
    def _key_variants(key: str) -> List[str]:
        variants = {FeatureExtractor._normalize_key(key)}
        parts = [part for part in re.split(r"[_\.\-]+", key) if part]
        if len(parts) > 1:
            for idx in range(1, len(parts)):
                variants.add(FeatureExtractor._normalize_key("_".join(parts[idx:])))
            variants.add(FeatureExtractor._normalize_key(parts[-1]))
        return [item for item in variants if item]

    @staticmethod
    def _merge_raw_wazuh_payload(combined: Dict[str, Any], metadata: Dict[str, Any]) -> None:
        payload = metadata.get("raw_wazuh_payload")
        if not isinstance(payload, dict):
            return

        for key in ("full_log", "location", "timestamp"):
            if key in payload:
                combined.setdefault(key, payload[key])

        for nested_key in ("data", "rule", "agent", "decoder"):
            nested = payload.get(nested_key)
            if not isinstance(nested, dict):
                continue
            for key, value in nested.items():
                combined.setdefault(key, value)
                combined.setdefault(f"{nested_key}_{key}", value)

    def _derive_http_proxy_features(self, combined: Dict[str, Any], log: Dict[str, Any]) -> None:
        full_log = combined.get("full_log")
        if not isinstance(full_log, str):
            full_log = log.get("message")
        if not isinstance(full_log, str):
            return

        parsed = self._parse_nginx_access_log(full_log)
        if parsed is None:
            return

        request_line = parsed["request_line"]
        method = parsed["method"]
        path = parsed["path"]
        status = parsed["status"]
        body_bytes = parsed["body_bytes"]
        user_agent = parsed["user_agent"]

        request_len = len(request_line)
        path_len = len(path)
        ua_len = len(user_agent)
        suspicious_path = 1.0 if self._has_suspicious_http_pattern(path) else 0.0

        combined.setdefault("total_fwd_packets", 1.0)
        combined.setdefault("total_backward_packets", 1.0)
        combined.setdefault("total_length_of_fwd_packets", float(request_len))
        combined.setdefault("total_length_of_bwd_packets", float(body_bytes))
        combined.setdefault("fwd_packet_length_max", float(request_len))
        combined.setdefault("fwd_packet_length_min", float(request_len))
        combined.setdefault("fwd_packet_length_mean", float(request_len))
        combined.setdefault("bwd_packet_length_max", float(body_bytes))
        combined.setdefault("bwd_packet_length_min", float(body_bytes))
        combined.setdefault("bwd_packet_length_mean", float(body_bytes))
        combined.setdefault("min_packet_length", float(min(request_len, body_bytes)))
        combined.setdefault("max_packet_length", float(max(request_len, body_bytes)))
        combined.setdefault("packet_length_mean", float((request_len + body_bytes) / 2.0))
        combined.setdefault("packet_length_variance", float(abs(request_len - body_bytes)))
        combined.setdefault("average_packet_size", float((request_len + body_bytes) / 2.0))
        combined.setdefault("subflow_fwd_packets", 1.0)
        combined.setdefault("subflow_bwd_packets", 1.0)
        combined.setdefault("subflow_fwd_bytes", float(request_len))
        combined.setdefault("subflow_bwd_bytes", float(body_bytes))
        combined.setdefault("flow_duration", float(max(path_len + ua_len, 1)))
        combined.setdefault("flow_bytes_sec", float(request_len + body_bytes))
        combined.setdefault("flow_packets_sec", 2.0)
        combined.setdefault("fwd_packets_sec", 1.0)
        combined.setdefault("bwd_packets_sec", 1.0)
        combined.setdefault("flow_iat_mean", float(max(path_len, 1)))
        combined.setdefault("flow_iat_std", float(path_len / 2.0))
        combined.setdefault("flow_iat_max", float(max(path_len, ua_len, 1)))
        combined.setdefault("flow_iat_min", 1.0)
        combined.setdefault("fwd_iat_total", float(max(path_len, 1)))
        combined.setdefault("fwd_iat_mean", float(max(path_len, 1)))
        combined.setdefault("fwd_iat_std", float(path_len / 3.0))
        combined.setdefault("fwd_iat_max", float(max(path_len, 1)))
        combined.setdefault("fwd_iat_min", 1.0)
        combined.setdefault("bwd_iat_total", float(max(ua_len, 1)))
        combined.setdefault("bwd_iat_mean", float(max(ua_len, 1)))
        combined.setdefault("bwd_iat_std", float(ua_len / 3.0))
        combined.setdefault("bwd_iat_max", float(max(ua_len, 1)))
        combined.setdefault("bwd_iat_min", 1.0)
        combined.setdefault("init_win_bytes_forward", float(min(request_len, 65535)))
        combined.setdefault("init_win_bytes_backward", float(min(body_bytes, 65535)))
        combined.setdefault("act_data_pkt_fwd", 1.0)
        combined.setdefault("min_seg_size_forward", float(max(min(request_len, 1500), 1)))
        combined.setdefault("active_mean", float(max(path_len, 1)))
        combined.setdefault("active_std", float(path_len / 2.0))
        combined.setdefault("active_max", float(max(path_len, ua_len, 1)))
        combined.setdefault("active_min", 1.0)
        combined.setdefault("idle_mean", float(max(ua_len, 1)))
        combined.setdefault("idle_std", float(ua_len / 2.0))
        combined.setdefault("idle_max", float(max(ua_len, 1)))
        combined.setdefault("idle_min", 1.0)
        combined.setdefault("ack_flag_count", 1.0 if status >= 200 else 0.0)
        combined.setdefault("syn_flag_count", 1.0 if method == "GET" else 0.0)
        combined.setdefault("psh_flag_count", suspicious_path)
        combined.setdefault("rst_flag_count", 1.0 if status >= 400 else 0.0)
        combined.setdefault("urg_flag_count", 1.0 if method == "POST" else 0.0)
        combined.setdefault("ece_flag_count", suspicious_path)
        combined.setdefault("fwd_psh_flags", suspicious_path)
        combined.setdefault("bwd_psh_flags", suspicious_path)
        combined.setdefault("down_up_ratio", float(body_bytes / max(request_len, 1)))

    @staticmethod
    def _parse_nginx_access_log(line: str) -> Dict[str, Any] | None:
        line = line.strip()
        # Format: ip - - [time] "METHOD /path HTTP/1.1" status bytes "ref" "ua"
        pattern = re.compile(
            r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
        )
        match = pattern.match(line)
        if not match:
            return None

        request_line = match.group("request").strip()
        request_parts = request_line.split()
        method = request_parts[0].upper() if request_parts else ""
        path = request_parts[1] if len(request_parts) > 1 else ""
        try:
            status = int(match.group("status"))
        except ValueError:
            status = 0
        byte_token = match.group("bytes")
        try:
            body_bytes = int(byte_token)
        except ValueError:
            body_bytes = 0
        return {
            "request_line": request_line,
            "method": method,
            "path": path,
            "status": status,
            "body_bytes": body_bytes,
            "user_agent": match.group("ua"),
        }

    @staticmethod
    def _has_suspicious_http_pattern(path: str) -> bool:
        lowered = path.lower()
        indicators = (
            "..",
            "%2e%2e",
            "wp-config",
            "localsettings",
            ".htaccess",
            "config.php",
            ".bak",
            ".old",
            ".swp",
            "copy%20of",
            "%23",
        )
        return any(token in lowered for token in indicators)

    def _extract_feature_value(self, feature_name: str, lookup: Dict[str, Any]) -> float:
        primary = self._normalize_key(feature_name)
        if primary in lookup:
            return self._to_float(lookup[primary])

        for alias in self.KEY_ALIASES.get(primary, []):
            alias_key = self._normalize_key(alias)
            if alias_key in lookup:
                return self._to_float(lookup[alias_key])
        return 0.0

    def _to_float(self, value: Any) -> float:
        if value is None:
            return 0.0
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            if np.isnan(value) or np.isinf(value):
                return 0.0
            return float(value)
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return 0.0
            severity_val = self._severity_map.get(stripped.lower())
            if severity_val is not None:
                return severity_val
            try:
                numeric = float(stripped.replace(",", ""))
                if np.isnan(numeric) or np.isinf(numeric):
                    return 0.0
                return float(numeric)
            except ValueError:
                return 0.0
        return 0.0
