import math
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlparse


class WazuhFamilyFeatureEngineer:
    FAMILY_WEB_ACCESS = "web_access"
    FAMILY_AUTH = "auth"
    FAMILY_HOST = "host_telemetry"
    FAMILY_INTEGRITY = "integrity_compliance"

    SCHEMA_BY_FAMILY = {
        FAMILY_WEB_ACCESS: "web_access_v1",
        FAMILY_AUTH: "auth_v1",
        FAMILY_HOST: "host_telemetry_v1",
        FAMILY_INTEGRITY: "integrity_compliance_v1",
    }

    DECODER_TO_FAMILY = {
        "web-accesslog": FAMILY_WEB_ACCESS,
        "pam": FAMILY_AUTH,
        "sudo": FAMILY_AUTH,
        "sshd": FAMILY_AUTH,
        "systemd": FAMILY_HOST,
        "kernel": FAMILY_HOST,
        "ossec": FAMILY_HOST,
        "syscollector": FAMILY_HOST,
        "sca": FAMILY_INTEGRITY,
        "rootcheck": FAMILY_INTEGRITY,
        "json": FAMILY_INTEGRITY,
        "syscheck": FAMILY_INTEGRITY,
    }

    _HTTP_LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"(?P<referrer>[^"]*)"\s+"(?P<ua>[^"]*)"'
    )
    _PATH_ID_RE = re.compile(r"/(?:\d+|[0-9a-f]{8,}|[A-Za-z0-9_-]{24,})(?=/|$)")
    _PATH_NUMERIC_RE = re.compile(r"\b\d+\b")
    _SUSPICIOUS_HTTP_TOKENS = (
        "..",
        "%2e%2e",
        "wp-login.php",
        "wp-json",
        ".git/",
        "boot.ini",
        "etc/passwd",
        "updatexml",
        "union select",
        "localsettings",
        "config.php",
        ".bak",
        ".old",
        ".swp",
        "author=",
    )
    _AUTH_FAILURE_PATTERNS = (
        "failed password",
        "authentication failure",
        "invalid user",
        "incorrect password",
        "not in sudoers",
        "failure",
        "failed",
    )
    _AUTH_SUCCESS_PATTERNS = (
        "accepted password",
        "session opened",
        "authentication succeeded",
        "sudo:",
        "command=",
    )
    _HOST_PATH_RE = re.compile(r"(/[\w\-.~/]+)")
    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _WORD_RE = re.compile(r"[A-Za-z0-9_:/.-]+")

    def family_for_payload(self, payload: Dict[str, Any]) -> Optional[str]:
        decoder = self._decoder_name(payload)
        if decoder in self.DECODER_TO_FAMILY:
            return self.DECODER_TO_FAMILY[decoder]
        location = str(payload.get("location") or "").strip().lower()
        if "nginx" in location or "access" in location:
            return self.FAMILY_WEB_ACCESS
        return None

    def family_for_log(self, log: Dict[str, Any]) -> Optional[str]:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict):
            family = metadata.get("model_family")
            if isinstance(family, str) and family.strip():
                return family.strip()
            payload = metadata.get("raw_wazuh_payload")
            if isinstance(payload, dict):
                return self.family_for_payload(payload)
        return None

    def schema_for_family(self, family: Optional[str]) -> Optional[str]:
        if not family:
            return None
        return self.SCHEMA_BY_FAMILY.get(family)

    def engineer_payload(self, payload: Dict[str, Any], message_override: Optional[str] = None) -> Dict[str, Any]:
        family = self.family_for_payload(payload)
        schema = self.schema_for_family(family)
        if not family or not schema:
            return {
                "model_family": None,
                "feature_schema_version": None,
                "engineered_features": {},
                "routing_reason": "unsupported_decoder_family",
            }

        message = str(message_override or payload.get("full_log") or payload.get("rule", {}).get("description") or "")
        feature_payload = self._build_family_features(family, payload, message)
        return {
            "model_family": family,
            "feature_schema_version": schema,
            "engineered_features": {schema: feature_payload},
            "routing_reason": "eligible_for_family_pipeline",
        }

    def build_prediction_payload(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        metadata = log.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None

        family = metadata.get("model_family")
        schema = metadata.get("feature_schema_version")
        engineered = metadata.get("engineered_features")
        if (
            isinstance(family, str)
            and isinstance(schema, str)
            and isinstance(engineered, dict)
            and isinstance(engineered.get(schema), dict)
        ):
            return {
                "model_family": family,
                "feature_schema_version": schema,
                "sample": engineered[schema],
            }

        payload = metadata.get("raw_wazuh_payload")
        if not isinstance(payload, dict):
            return None
        engineered_bundle = self.engineer_payload(payload, message_override=self._preferred_message_for_log(log, payload))
        family = engineered_bundle.get("model_family")
        schema = engineered_bundle.get("feature_schema_version")
        nested = engineered_bundle.get("engineered_features") or {}
        if not isinstance(family, str) or not isinstance(schema, str):
            return None
        sample = nested.get(schema)
        if not isinstance(sample, dict):
            return None
        return {
            "model_family": family,
            "feature_schema_version": schema,
            "sample": sample,
        }

    @staticmethod
    def _preferred_message_for_log(log: Dict[str, Any], payload: Dict[str, Any]) -> str:
        full_log = str(payload.get("full_log") or "").strip()
        if full_log:
            return full_log
        description = str((payload.get("rule") or {}).get("description") or "").strip()
        if description:
            return description
        return str(log.get("message") or "")

    def _build_family_features(self, family: str, payload: Dict[str, Any], message: str) -> Dict[str, Dict[str, Any]]:
        if family == self.FAMILY_WEB_ACCESS:
            return self._build_web_access_features(payload, message)
        if family == self.FAMILY_AUTH:
            return self._build_auth_features(payload, message)
        if family == self.FAMILY_HOST:
            return self._build_host_features(payload, message)
        return self._build_integrity_features(payload, message)

    def _build_web_access_features(self, payload: Dict[str, Any], message: str) -> Dict[str, Dict[str, Any]]:
        parsed = self._parse_http_access_line(message)
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        timestamp = self._parse_timestamp(payload.get("timestamp"))
        path = parsed.get("path", "")
        parsed_url = urlparse(path if isinstance(path, str) else "")
        query_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
        query_keys = [key for key, _ in query_pairs]
        query_values = [value for _, value in query_pairs]
        suspicious_hits = [token for token in self._SUSPICIOUS_HTTP_TOKENS if token in path.lower()]
        method = str(parsed.get("method") or "").upper()
        status = self._to_int(parsed.get("status"))
        body_bytes = self._to_int(parsed.get("body_bytes"))
        request_line = str(parsed.get("request_line") or "")
        user_agent = str(parsed.get("user_agent") or "")
        referrer = str(parsed.get("referrer") or "")
        host = str(parsed.get("ip") or payload.get("srcip") or "")

        numeric = {
            "rule_level": float(self._to_int(rule.get("level"))),
            "hour_of_day": float(timestamp.hour if timestamp else 0),
            "weekday": float(timestamp.weekday() if timestamp else 0),
            "status_code": float(status),
            "status_class": float(status // 100 if status else 0),
            "body_bytes": float(body_bytes),
            "request_length": float(len(request_line)),
            "path_length": float(len(parsed_url.path or path)),
            "query_length": float(len(parsed_url.query)),
            "query_param_count": float(len(query_pairs)),
            "query_key_count": float(len(set(query_keys))),
            "suspicious_token_count": float(len(suspicious_hits)),
            "path_depth": float(len([part for part in parsed_url.path.split("/") if part])),
            "message_length": float(len(message)),
            "referrer_present": 1.0 if referrer and referrer != "-" else 0.0,
            "has_query": 1.0 if parsed_url.query else 0.0,
            "is_rest_endpoint": 1.0 if parsed_url.path.startswith("/rest/") else 0.0,
            "is_socket_io": 1.0 if parsed_url.path.startswith("/socket.io/") else 0.0,
            "is_asset_request": 1.0 if self._looks_like_asset(parsed_url.path) else 0.0,
            "is_error_status": 1.0 if status >= 400 else 0.0,
            "empty_response": 1.0 if body_bytes == 0 else 0.0,
            "query_entropy": self._shannon_entropy("&".join(query_values)) if query_values else 0.0,
            "path_entropy": self._shannon_entropy(parsed_url.path) if parsed_url.path else 0.0,
        }
        categorical = {
            "method": method or "UNKNOWN",
            "route_template": self._normalize_route_template(parsed_url.path or path or "/"),
            "user_agent_family": self._user_agent_family(user_agent),
            "status_bucket": f"{status // 100}xx" if status else "unknown",
            "file_extension": self._file_extension(parsed_url.path),
            "agent_name": self._agent_name(payload),
            "origin": str(payload.get("location") or ""),
            "host_ip": host,
        }
        text = {
            "message": message[:2000],
            "path": (parsed_url.path or path or "")[:1000],
            "query": parsed_url.query[:1000],
            "user_agent": user_agent[:500],
        }
        return {"numeric": numeric, "categorical": categorical, "text": text}

    def _build_auth_features(self, payload: Dict[str, Any], message: str) -> Dict[str, Dict[str, Any]]:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        timestamp = self._parse_timestamp(payload.get("timestamp"))
        lowered = message.lower()
        account = self._extract_account(message)
        action = self._extract_auth_action(message)
        result = self._extract_auth_result(lowered)
        source_ip = self._first_ip(message) or str((payload.get("data") or {}).get("srcip") or "")
        numeric = {
            "rule_level": float(self._to_int(rule.get("level"))),
            "hour_of_day": float(timestamp.hour if timestamp else 0),
            "weekday": float(timestamp.weekday() if timestamp else 0),
            "message_length": float(len(message)),
            "word_count": float(len(self._WORD_RE.findall(message))),
            "has_source_ip": 1.0 if source_ip else 0.0,
            "is_failure": 1.0 if result == "failure" else 0.0,
            "is_success": 1.0 if result == "success" else 0.0,
            "is_privilege_escalation": 1.0 if action == "sudo" else 0.0,
        }
        categorical = {
            "decoder_name": self._decoder_name(payload) or "unknown",
            "agent_name": self._agent_name(payload),
            "action": action,
            "result": result,
            "account": account,
            "source_ip": source_ip,
            "location": str(payload.get("location") or ""),
        }
        text = {
            "message": message[:2000],
            "title": str((payload.get("data") or {}).get("title") or "")[:1000],
        }
        return {"numeric": numeric, "categorical": categorical, "text": text}

    def _build_host_features(self, payload: Dict[str, Any], message: str) -> Dict[str, Dict[str, Any]]:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        timestamp = self._parse_timestamp(payload.get("timestamp"))
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        paths = self._HOST_PATH_RE.findall(message)
        numeric = {
            "rule_level": float(self._to_int(rule.get("level"))),
            "hour_of_day": float(timestamp.hour if timestamp else 0),
            "weekday": float(timestamp.weekday() if timestamp else 0),
            "message_length": float(len(message)),
            "word_count": float(len(self._WORD_RE.findall(message))),
            "path_count": float(len(paths)),
            "has_process_name": 1.0 if data.get("name") or data.get("program_name") else 0.0,
            "has_package_name": 1.0 if data.get("package") or data.get("pkgname") else 0.0,
            "has_ip_address": 1.0 if self._first_ip(message) else 0.0,
        }
        categorical = {
            "decoder_name": self._decoder_name(payload) or "unknown",
            "agent_name": self._agent_name(payload),
            "rule_id": str(rule.get("id") or ""),
            "rule_group": self._rule_group(rule),
            "location": str(payload.get("location") or ""),
            "program_name": str(data.get("program_name") or data.get("name") or ""),
            "severity": self._severity_bucket(rule),
        }
        text = {
            "message": message[:2000],
            "title": str(data.get("title") or "")[:1000],
            "paths": " ".join(paths[:20])[:1000],
        }
        return {"numeric": numeric, "categorical": categorical, "text": text}

    def _build_integrity_features(self, payload: Dict[str, Any], message: str) -> Dict[str, Dict[str, Any]]:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        timestamp = self._parse_timestamp(payload.get("timestamp"))
        target = str(data.get("file") or data.get("path") or data.get("check") or "")
        result = str(data.get("result") or data.get("status") or "").strip().lower()
        numeric = {
            "rule_level": float(self._to_int(rule.get("level"))),
            "hour_of_day": float(timestamp.hour if timestamp else 0),
            "weekday": float(timestamp.weekday() if timestamp else 0),
            "message_length": float(len(message)),
            "word_count": float(len(self._WORD_RE.findall(message))),
            "target_path_length": float(len(target)),
            "has_target_path": 1.0 if target else 0.0,
            "is_failed_result": 1.0 if result in {"fail", "failed", "invalid", "error"} else 0.0,
            "is_passed_result": 1.0 if result in {"pass", "passed", "ok", "success"} else 0.0,
        }
        categorical = {
            "decoder_name": self._decoder_name(payload) or "unknown",
            "agent_name": self._agent_name(payload),
            "rule_id": str(rule.get("id") or ""),
            "rule_group": self._rule_group(rule),
            "location": str(payload.get("location") or ""),
            "result": result or "unknown",
            "target": target[:200],
            "severity": self._severity_bucket(rule),
        }
        text = {
            "message": message[:2000],
            "title": str(data.get("title") or "")[:1000],
            "target": target[:1000],
        }
        return {"numeric": numeric, "categorical": categorical, "text": text}

    def _decoder_name(self, payload: Dict[str, Any]) -> str:
        decoder = payload.get("decoder")
        if isinstance(decoder, dict):
            return str(decoder.get("name") or "").strip().lower()
        return ""

    @staticmethod
    def _agent_name(payload: Dict[str, Any]) -> str:
        agent = payload.get("agent")
        if isinstance(agent, dict):
            return str(agent.get("name") or "").strip()
        return ""

    @staticmethod
    def _rule_group(rule: Dict[str, Any]) -> str:
        groups = rule.get("groups")
        if isinstance(groups, list):
            return ",".join(str(item).strip() for item in groups if str(item).strip())[:300]
        return ""

    @staticmethod
    def _severity_bucket(rule: Dict[str, Any]) -> str:
        level = int(rule.get("level", 0) or 0)
        if level >= 12:
            return "critical"
        if level >= 8:
            return "high"
        if level >= 4:
            return "medium"
        return "low"

    def _parse_http_access_line(self, line: str) -> Dict[str, Any]:
        match = self._HTTP_LOG_PATTERN.match(line.strip())
        if not match:
            return {
                "ip": "",
                "request_line": "",
                "method": "",
                "path": "",
                "status": 0,
                "body_bytes": 0,
                "referrer": "",
                "user_agent": "",
            }
        request_line = match.group("request").strip()
        parts = request_line.split()
        method = parts[0].upper() if parts else ""
        path = parts[1] if len(parts) > 1 else ""
        return {
            "ip": match.group("ip"),
            "request_line": request_line,
            "method": method,
            "path": path,
            "status": self._to_int(match.group("status")),
            "body_bytes": self._to_int(match.group("bytes")),
            "referrer": match.group("referrer"),
            "user_agent": match.group("ua"),
        }

    @staticmethod
    def _to_int(value: Any) -> int:
        try:
            return int(float(str(value).strip()))
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            return None
        raw = value.strip().replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", raw):
            raw = f"{raw[:-5]}{raw[-5:-2]}:{raw[-2:]}"
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None

    @classmethod
    def _normalize_route_template(cls, path: str) -> str:
        normalized = cls._PATH_ID_RE.sub("/:id", path or "/")
        normalized = cls._PATH_NUMERIC_RE.sub(":n", normalized)
        return normalized[:300] or "/"

    @staticmethod
    def _user_agent_family(user_agent: str) -> str:
        lowered = user_agent.lower()
        if "nmap scripting engine" in lowered:
            return "nmap"
        if "sqlmap" in lowered:
            return "sqlmap"
        if "nikto" in lowered:
            return "nikto"
        if "curl" in lowered:
            return "curl"
        if "python-requests" in lowered:
            return "python_requests"
        if "firefox" in lowered:
            return "firefox"
        if "chrome" in lowered or "chromium" in lowered:
            return "chrome"
        if "safari" in lowered:
            return "safari"
        if "mozilla" in lowered:
            return "browser_other"
        return "unknown"

    @staticmethod
    def _file_extension(path: Optional[str]) -> str:
        if not path or "." not in path:
            return ""
        last = path.rsplit("/", 1)[-1]
        if "." not in last:
            return ""
        return last.rsplit(".", 1)[-1].lower()[:20]

    @staticmethod
    def _looks_like_asset(path: str) -> bool:
        lowered = path.lower()
        return lowered.endswith((".js", ".css", ".png", ".svg", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".json"))

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        entropy = 0.0
        total = len(value)
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return float(round(entropy, 6))

    @staticmethod
    def _extract_account(message: str) -> str:
        patterns = (
            r"for user (\S+)",
            r"user (\S+)",
            r"account (\S+)",
            r"sudo: (\S+)",
        )
        for pattern in patterns:
            match = re.search(pattern, message, flags=re.IGNORECASE)
            if match:
                return match.group(1)[:120]
        return ""

    @classmethod
    def _extract_auth_action(cls, message: str) -> str:
        lowered = message.lower()
        if "sudo" in lowered:
            return "sudo"
        if "sshd" in lowered or "ssh" in lowered:
            return "ssh"
        if "session opened" in lowered or "session closed" in lowered:
            return "session"
        return "auth"

    @classmethod
    def _extract_auth_result(cls, lowered: str) -> str:
        if any(token in lowered for token in cls._AUTH_FAILURE_PATTERNS):
            return "failure"
        if any(token in lowered for token in cls._AUTH_SUCCESS_PATTERNS):
            return "success"
        return "unknown"

    @classmethod
    def _first_ip(cls, message: str) -> str:
        match = cls._IP_RE.search(message)
        return match.group(0) if match else ""
