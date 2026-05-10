import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from app.ml.features.wazuh_feature_extractor import WazuhFeatureExtractor

CLASS_ORDER: List[str] = [
    "benign",
    "nosql_injection",
    "sql_injection",
    "xss",
    "csrf",
    "path_traversal",
    "file_inclusion",
    "command_injection",
    "ssh_bruteforce",
    "web_login_bruteforce",
    "password_spray",
    "account_enumeration",
    "credential_stuffing",
    "web_scanner",
    "nmap_basic_scan",
    "nmap_advanced_scan",
    "nmap_evasion_scan",
    "sensitive_file_probe",
    "suspicious_automation",
    "dos_http_flood",
    "ddos_l7_flood",
    "other_attack",
]


class WazuhDatasetBuilder:
    def __init__(self) -> None:
        self._extractor = WazuhFeatureExtractor()

    def build(self, raw_file_path: str, min_samples_per_class: int = 50) -> Dict[str, Any]:
        rows = self._load_rows(raw_file_path)
        if len(rows) < 50:
            raise RuntimeError("Raw Wazuh dataset is too small; expected at least 50 events")

        engineered_logs: List[Dict[str, Any]] = []
        labels_raw: List[str] = []
        confidence_counts = {"high": 0, "medium": 0, "low": 0}
        for row in rows:
            payload = self._normalize_payload(row)
            if not payload:
                continue
            log = self._to_log(payload)
            label, confidence = self._auto_label(payload, log)
            if confidence not in confidence_counts:
                confidence = "low"
            confidence_counts[confidence] += 1
            if confidence == "low" and label != "benign":
                label = "other_attack"
            engineered_logs.append(log)
            labels_raw.append(label)

        if len(engineered_logs) < 50:
            raise RuntimeError("No usable Wazuh events found in raw dataset")

        collapsed, collapse_map = self._collapse_rare_classes(labels_raw, min_samples_per_class)
        features = self._extractor.transform(engineered_logs)

        label_to_id = {name: idx for idx, name in enumerate(CLASS_ORDER)}
        encoded_labels = [label_to_id.get(name, label_to_id["other_attack"]) for name in collapsed]

        label_counts = Counter(collapsed)
        return {
            "reason": "wazuh_bootstrap_retrain",
            "feature_schema": self._extractor.SCHEMA_ID,
            "feature_names": list(self._extractor.FEATURE_NAMES),
            "features": features.tolist(),
            "labels": encoded_labels,
            "label_map": {str(idx): name.upper() for name, idx in label_to_id.items()},
            "report": {
                "samples": len(encoded_labels),
                "class_counts": dict(label_counts),
                "collapsed_classes": collapse_map,
                "confidence_distribution": confidence_counts,
                "source_path": raw_file_path,
            },
        }

    @staticmethod
    def _load_rows(raw_file_path: str) -> List[Any]:
        path = Path(raw_file_path)
        if not path.is_file():
            raise RuntimeError(f"Raw Wazuh dataset file not found: {raw_file_path}")

        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            raise RuntimeError("Raw Wazuh dataset file is empty")

        if text.startswith("["):
            data = json.loads(text)
            if isinstance(data, list):
                return data
            raise RuntimeError("Raw Wazuh dataset JSON root must be an array")

        rows: List[Any] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    @staticmethod
    def _normalize_payload(row: Any) -> Dict[str, Any] | None:
        if not isinstance(row, dict):
            return None
        if isinstance(row.get("payload"), dict):
            return row["payload"]
        if isinstance(row.get("metadata"), dict):
            raw = row["metadata"].get("raw_wazuh_payload")
            if isinstance(raw, dict):
                return raw
        if any(k in row for k in ("rule", "decoder", "agent", "full_log", "timestamp", "data")):
            return row
        return None

    @staticmethod
    def _to_log(payload: Dict[str, Any]) -> Dict[str, Any]:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
        message = str(rule.get("description") or payload.get("full_log") or "")
        return {
            "timestamp": payload.get("timestamp"),
            "source": str(agent.get("name") or "wazuh"),
            "message": message,
            "metadata": {"raw_wazuh_payload": payload},
        }

    def _auto_label(self, payload: Dict[str, Any], log: Dict[str, Any]) -> Tuple[str, str]:
        text = self._blob(payload, log)
        path = self._extract_path(text)

        if self._has_any(text, ("ddos", "distributed denial")):
            return ("ddos_l7_flood", "high")
        if self._has_any(text, ("dos", "http flood", "slowloris", "too many requests")):
            return ("dos_http_flood", "high")
        if self._has_any(text, ("nmap", "masscan")):
            if self._has_any(text, ("-f", "--mtu", "-D", "--source-port", "decoy")):
                return ("nmap_evasion_scan", "high")
            if self._has_any(text, ("-a", "-sv", "--script", "nse", "os detection")):
                return ("nmap_advanced_scan", "high")
            return ("nmap_basic_scan", "high")
        if self._has_any(text, ("gobuster", "skipfish", "wpscan", "nikto", "dirbuster", "whatweb", "sqlmap")):
            return ("web_scanner", "high")
        if self._has_any(text + " " + path, ("$ne", "$gt", "$where", "{\"$")):
            return ("nosql_injection", "high")
        if self._has_any(text + " " + path, ("union select", "sleep(", "benchmark(", "' or 1=1", "\" or 1=1", "select * from")):
            return ("sql_injection", "high")
        if self._has_any(text + " " + path, ("<script", "javascript:", "onerror=", "onload=", "%3cscript")):
            return ("xss", "high")
        if self._has_any(text, ("csrf", "cross site request forgery", "anti csrf")):
            return ("csrf", "medium")
        if self._has_any(path, ("../", "..%2f", "%2e%2e", "..\\", "%2e%2e%5c")):
            return ("path_traversal", "high")
        if self._has_any(text + " " + path, ("php://", "file://", "expect://", "include=", "require=")):
            return ("file_inclusion", "high")
        if self._has_any(text + " " + path, (";cat ", "|cat ", "&&id", ";id", "`id`", "cmd=", "bash -c")):
            return ("command_injection", "high")
        if self._has_any(text, ("failed password", "invalid user", "authentication failure", "sshd")):
            return ("ssh_bruteforce", "high")
        if self._has_any(text, ("login failed", "too many login", "admin login attempt")):
            return ("web_login_bruteforce", "medium")
        if self._has_any(text, ("password spray", "single password many users")):
            return ("password_spray", "medium")
        if self._has_any(text, ("user not found", "invalid username", "unknown user")):
            return ("account_enumeration", "medium")
        if self._has_any(text, ("credential stuffing", "combo list", "breached credentials")):
            return ("credential_stuffing", "medium")
        if self._has_any(path, (".env", "wp-config", ".git", ".htaccess", "config.php", ".bak", ".old")):
            return ("sensitive_file_probe", "high")

        is_suspicious = self._has_any(text + " " + path, ("scan", "exploit", "attack", "blocked", "denied", "malicious"))
        if is_suspicious:
            return ("suspicious_automation", "low")
        return ("benign", "high")

    @staticmethod
    def _collapse_rare_classes(labels: List[str], min_samples_per_class: int) -> Tuple[List[str], Dict[str, int]]:
        if min_samples_per_class <= 1:
            return labels, {}
        counts = Counter(labels)
        collapsed: Dict[str, int] = {}
        out = []
        for label in labels:
            if label in {"benign", "other_attack"}:
                out.append(label)
                continue
            if counts[label] < min_samples_per_class:
                collapsed[label] = counts[label]
                out.append("other_attack")
            else:
                out.append(label)
        return out, collapsed

    @staticmethod
    def _has_any(text: str, tokens: Iterable[str]) -> bool:
        lowered = text.lower()
        return any(token.lower() in lowered for token in tokens)

    @staticmethod
    def _blob(payload: Dict[str, Any], log: Dict[str, Any]) -> str:
        parts = [str(log.get("message") or "")]
        for key in ("full_log", "location", "srcip", "dstip"):
            parts.append(str(payload.get(key) or ""))
        for key in ("rule", "decoder", "agent", "data"):
            value = payload.get(key)
            if isinstance(value, dict):
                parts.append(json.dumps(value, ensure_ascii=True))
        return " ".join(parts).lower()

    @staticmethod
    def _extract_path(text: str) -> str:
        match = re.search(r"\"(?:get|post|put|delete|patch|head|options)\s+(\S+)", text, flags=re.IGNORECASE)
        return match.group(1).lower() if match else ""
