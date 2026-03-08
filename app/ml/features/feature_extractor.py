import logging
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
        "destinationport": ["dstport", "dport", "destination_port", "destport"],
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
        for key, value in log.items():
            if key in {"metadata", "message"}:
                continue
            combined[key] = value

        normalized: Dict[str, Any] = {}
        for key, value in combined.items():
            normalized[self._normalize_key(key)] = value
        return normalized

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
