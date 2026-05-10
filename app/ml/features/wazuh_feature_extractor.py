import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List

import numpy as np


class WazuhFeatureExtractor:
    SCHEMA_ID = "wazuh_native_v1"
    FEATURE_NAMES: List[str] = [
        "rule_level",
        "rule_firedtimes",
        "rule_id_numeric",
        "decoder_hash_bucket",
        "agent_hash_bucket",
        "message_len",
        "path_len",
        "query_len",
        "http_method_code",
        "http_status",
        "body_bytes",
        "has_sql_keyword",
        "has_nosql_keyword",
        "has_xss_keyword",
        "has_csrf_keyword",
        "has_traversal_keyword",
        "has_file_inclusion_keyword",
        "has_cmd_injection_keyword",
        "has_bruteforce_keyword",
        "has_password_spray_keyword",
        "has_account_enum_keyword",
        "has_credential_stuffing_keyword",
        "has_web_scanner_keyword",
        "has_nmap_keyword",
        "has_nmap_aggressive",
        "has_nmap_evasion",
        "has_sensitive_file_probe_keyword",
        "has_dos_keyword",
        "has_ddos_keyword",
        "src_seen_count",
        "dst_seen_count",
        "ua_seen_count",
        "source_event_count",
        "events_same_minute",
        "timestamp_hour",
        "is_weekend",
        "is_error_status",
        "is_auth_related",
        "is_web_related",
        "is_suspicious_path",
    ]

    _METHOD_CODE = {
        "GET": 1.0,
        "POST": 2.0,
        "PUT": 3.0,
        "DELETE": 4.0,
        "PATCH": 5.0,
        "HEAD": 6.0,
        "OPTIONS": 7.0,
    }

    def transform(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        if not logs:
            return np.zeros((0, len(self.FEATURE_NAMES)), dtype=float)

        src_counter: Counter[str] = Counter()
        dst_counter: Counter[str] = Counter()
        ua_counter: Counter[str] = Counter()
        source_counter: Counter[str] = Counter()
        minute_counter: Counter[str] = Counter()

        parsed_rows: List[Dict[str, Any]] = []
        for log in logs:
            row = self._extract_row(log)
            parsed_rows.append(row)
            src_counter.update([row["src"]])
            dst_counter.update([row["dst"]])
            ua_counter.update([row["ua"]])
            source_counter.update([row["source"]])
            minute_counter.update([row["minute_key"]])

        features: List[List[float]] = []
        for row in parsed_rows:
            features.append(
                [
                    row["rule_level"],
                    row["rule_firedtimes"],
                    row["rule_id_numeric"],
                    row["decoder_hash_bucket"],
                    row["agent_hash_bucket"],
                    row["message_len"],
                    row["path_len"],
                    row["query_len"],
                    row["http_method_code"],
                    row["http_status"],
                    row["body_bytes"],
                    row["has_sql_keyword"],
                    row["has_nosql_keyword"],
                    row["has_xss_keyword"],
                    row["has_csrf_keyword"],
                    row["has_traversal_keyword"],
                    row["has_file_inclusion_keyword"],
                    row["has_cmd_injection_keyword"],
                    row["has_bruteforce_keyword"],
                    row["has_password_spray_keyword"],
                    row["has_account_enum_keyword"],
                    row["has_credential_stuffing_keyword"],
                    row["has_web_scanner_keyword"],
                    row["has_nmap_keyword"],
                    row["has_nmap_aggressive"],
                    row["has_nmap_evasion"],
                    row["has_sensitive_file_probe_keyword"],
                    row["has_dos_keyword"],
                    row["has_ddos_keyword"],
                    float(src_counter[row["src"]]),
                    float(dst_counter[row["dst"]]),
                    float(ua_counter[row["ua"]]),
                    float(source_counter[row["source"]]),
                    float(minute_counter[row["minute_key"]]),
                    row["timestamp_hour"],
                    row["is_weekend"],
                    row["is_error_status"],
                    row["is_auth_related"],
                    row["is_web_related"],
                    row["is_suspicious_path"],
                ]
            )
        return np.asarray(features, dtype=float)

    def _extract_row(self, log: Dict[str, Any]) -> Dict[str, float | str]:
        metadata = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
        raw = metadata.get("raw_wazuh_payload") if isinstance(metadata.get("raw_wazuh_payload"), dict) else {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        decoder = raw.get("decoder") if isinstance(raw.get("decoder"), dict) else {}
        agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}

        message = str(log.get("message") or raw.get("full_log") or rule.get("description") or "")
        lowered = message.lower()
        path = self._extract_path(message)
        path_lowered = path.lower()
        query_len = float(len(path.split("?", 1)[1])) if "?" in path else 0.0

        method = self._extract_method(message)
        status = self._extract_status(message)
        body_bytes = self._extract_bytes(message)

        timestamp = self._extract_timestamp(log, raw)
        minute_key = timestamp.strftime("%Y-%m-%dT%H:%M")

        src = str(data.get("srcip") or raw.get("srcip") or "")
        dst = str(data.get("dstip") or raw.get("dstip") or "")
        ua = self._extract_user_agent(message)
        source = str(log.get("source") or agent.get("name") or "unknown")
        decoder_name = str(decoder.get("name") or "")
        agent_name = str(agent.get("name") or "")

        auth_blob = " ".join(
            [lowered, str(raw.get("location") or "").lower(), str(decoder_name).lower(), str(rule.get("description") or "").lower()]
        )

        return {
            "rule_level": float(self._to_int(rule.get("level"))),
            "rule_firedtimes": float(self._to_int(rule.get("firedtimes"))),
            "rule_id_numeric": float(self._stable_bucket(str(rule.get("id") or ""), 997)),
            "decoder_hash_bucket": float(self._stable_bucket(decoder_name, 997)),
            "agent_hash_bucket": float(self._stable_bucket(agent_name, 997)),
            "message_len": float(len(message)),
            "path_len": float(len(path)),
            "query_len": query_len,
            "http_method_code": self._METHOD_CODE.get(method, 0.0),
            "http_status": float(status),
            "body_bytes": float(body_bytes),
            "has_sql_keyword": self._flag(path_lowered + " " + lowered, (r"\bunion\b", r"select.+from", "sleep(", "benchmark(", "' or 1=1", "\" or 1=1")),
            "has_nosql_keyword": self._flag(path_lowered + " " + lowered, ("$ne", "$gt", "$where", "mongodb", "nosql", "{\"$")),
            "has_xss_keyword": self._flag(path_lowered + " " + lowered, ("<script", "javascript:", "onerror=", "onload=", "%3cscript")),
            "has_csrf_keyword": self._flag(lowered, ("csrf", "cross site request forgery", "invalid anti csrf")),
            "has_traversal_keyword": self._flag(path_lowered, ("../", "..%2f", "%2e%2e", "..\\", "%2e%2e%5c")),
            "has_file_inclusion_keyword": self._flag(path_lowered + " " + lowered, ("php://", "file://", "expect://", "include=", "require=")),
            "has_cmd_injection_keyword": self._flag(path_lowered + " " + lowered, (";cat ", "|cat ", "&&id", ";id", "`id`", "cmd=", "bash -c")),
            "has_bruteforce_keyword": self._flag(auth_blob, ("failed password", "authentication failure", "invalid user", "login failed", "brute force")),
            "has_password_spray_keyword": self._flag(auth_blob, ("password spray", "many users", "single password")),
            "has_account_enum_keyword": self._flag(auth_blob, ("user not found", "unknown user", "invalid username", "account does not exist")),
            "has_credential_stuffing_keyword": self._flag(auth_blob, ("credential stuffing", "combo list", "breached credentials")),
            "has_web_scanner_keyword": self._flag(lowered, ("gobuster", "skipfish", "wpscan", "nikto", "dirbuster", "whatweb", "sqlmap")),
            "has_nmap_keyword": self._flag(lowered, ("nmap", "masscan", "syn scan", "tcp scan")),
            "has_nmap_aggressive": self._flag(lowered, ("-a", "-sV", "--script", "nse", "os detection", "version detection")),
            "has_nmap_evasion": self._flag(lowered, ("-sS", "-f", "--mtu", "--data-length", "-D", "--source-port", "decoy")),
            "has_sensitive_file_probe_keyword": self._flag(path_lowered, (".env", "wp-config", ".git", ".htaccess", "config.php", "backup", ".bak")),
            "has_dos_keyword": self._flag(lowered, ("dos", "slowloris", "http flood", "too many requests", "rate limit")),
            "has_ddos_keyword": self._flag(lowered, ("ddos", "distributed denial", "botnet flood")),
            "src": src or "none",
            "dst": dst or "none",
            "ua": ua or "none",
            "source": source or "none",
            "minute_key": minute_key,
            "timestamp_hour": float(timestamp.hour),
            "is_weekend": 1.0 if timestamp.weekday() >= 5 else 0.0,
            "is_error_status": 1.0 if status >= 400 else 0.0,
            "is_auth_related": self._flag(auth_blob, ("sshd", "pam", "auth", "login", "sudo")),
            "is_web_related": self._flag(" ".join([path_lowered, lowered, decoder_name.lower()]), ("http", "nginx", "apache", "web", "/")),
            "is_suspicious_path": self._flag(path_lowered, ("../", "%2e%2e", ".bak", ".old", "/admin", "/wp-", "/phpmyadmin")),
        }

    @staticmethod
    def _to_int(value: Any) -> int:
        try:
            return int(str(value).strip())
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _flag(text: str, needles: tuple[str, ...]) -> float:
        text = text.lower()
        return 1.0 if any(token in text for token in needles) else 0.0

    @staticmethod
    def _stable_bucket(value: str, mod: int) -> int:
        if not value:
            return 0
        return abs(hash(value)) % mod

    @staticmethod
    def _extract_path(message: str) -> str:
        m = re.search(r"\"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)", message)
        return m.group(1) if m else ""

    @staticmethod
    def _extract_method(message: str) -> str:
        m = re.search(r"\"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+", message, flags=re.IGNORECASE)
        return m.group(1).upper() if m else ""

    @staticmethod
    def _extract_status(message: str) -> int:
        m = re.search(r"\"\s+(\d{3})\s+", message)
        if not m:
            return 0
        try:
            return int(m.group(1))
        except ValueError:
            return 0

    @staticmethod
    def _extract_bytes(message: str) -> int:
        m = re.search(r"\"\s+\d{3}\s+(\d+|-)\s+", message)
        if not m:
            return 0
        token = m.group(1)
        if token == "-":
            return 0
        try:
            return int(token)
        except ValueError:
            return 0

    @staticmethod
    def _extract_user_agent(message: str) -> str:
        parts = re.findall(r"\"([^\"]*)\"", message)
        if len(parts) >= 3:
            return parts[-1]
        return ""

    @staticmethod
    def _extract_timestamp(log: Dict[str, Any], raw: Dict[str, Any]) -> datetime:
        candidates = [log.get("timestamp"), raw.get("timestamp")]
        for value in candidates:
            if isinstance(value, datetime):
                return value
            if isinstance(value, str):
                v = value.strip().replace("Z", "+00:00")
                try:
                    return datetime.fromisoformat(v)
                except ValueError:
                    continue
        return datetime.utcnow()
