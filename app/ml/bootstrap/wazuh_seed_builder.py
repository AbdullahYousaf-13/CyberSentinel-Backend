from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.ml_promotion_service import MLPromotionService

_HTTP_REQUEST_RE = re.compile(r'^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>\S+)\s+(?P<path>[^\s"]+)')


class WazuhBootstrapDatasetBuilder:
    GENERIC_ATTACK_LABEL_BY_FAMILY = {
        WazuhFamilyFeatureEngineer.FAMILY_WEB_ACCESS: "WEB_ATTACK_GENERIC",
        WazuhFamilyFeatureEngineer.FAMILY_AUTH: "AUTH_ATTACK_GENERIC",
        WazuhFamilyFeatureEngineer.FAMILY_HOST: "HOST_ATTACK_GENERIC",
        WazuhFamilyFeatureEngineer.FAMILY_INTEGRITY: "INTEGRITY_ALERT_GENERIC",
    }

    WEB_ACCESS_RULES: List[Tuple[str, List[str]]] = [
        ("PATH_TRAVERSAL", [r"\.\.", r"%2e%2e", r"boot\.ini", r"etc/passwd", r"%00"]),
        ("WORDPRESS_PROBE", [r"wp-login\.php", r"wp-json", r"\?author="]),
        ("GIT_PROBE", [r"\.git/"]),
        ("WEBDAV_PROBE", [r"^PROPFIND\b"]),
        (
            "PROXY_SPIDER_PROBE",
            [r"^https?://", r"www\.google\.com:80", r"www\.wikipedia\.org:80", r"www\.computerhistory\.org:80", r"@localhost"],
        ),
        ("SQLI_PROBE", [r"updatexml", r"union(?:\+|%20)select"]),
        ("PHPMYADMIN_PROBE", [r"phpMyAdmin"]),
        ("COLDFUSION_PROBE", [r"/CFIDE/", r"coldfusion"]),
        ("PHP_INJECTION_PROBE", [r"allow_url_include", r"auto_prepend_file=php://input"]),
        ("CGI_PROBE", [r"/cgi-bin/"]),
    ]
    AUTH_RULES: List[Tuple[str, List[str]]] = [
        ("AUTH_LOGIN_FAILURE", [r"user login failed", r"failed password", r"authentication failure"]),
        ("SSH_INVALID_USER", [r"failed password for invalid user", r"\binvalid user\b"]),
        ("SUDO_POLICY_VIOLATION", [r"not in sudoers", r"sudo:.*authentication failure"]),
        ("AUTH_BRUTE_FORCE", [r"too many authentication failures", r"maximum authentication attempts"]),
    ]
    HOST_RULES: List[Tuple[str, List[str]]] = [
        ("ROOTKIT_INDICATOR", [r"rootkit", r"hidden process", r"hidden file", r"suspicious kernel module"]),
        ("MALWARE_INDICATOR", [r"malware", r"trojan", r"ransomware", r"\bworm\b"]),
        ("PERSISTENCE_INDICATOR", [r"unauthorized cron", r"suspicious startup", r"backdoor"]),
    ]
    INTEGRITY_RULES: List[Tuple[str, List[str]]] = [
        ("ROOTCHECK_FINDING", [r"rootkit", r"hidden process", r"hidden file", r"suspicious file"]),
        ("INTEGRITY_TAMPERING", [r"checksum changed", r"integrity (?:is )?compromised", r"sha\d{1,3} changed", r"md5 changed"]),
        ("SCA_POLICY_FAILURE", [r"score less than 50%", r"status changed from failed to passed", r"status changed from passed to failed"]),
    ]

    def __init__(self, engineer: Optional[WazuhFamilyFeatureEngineer] = None) -> None:
        self._engineer = engineer or WazuhFamilyFeatureEngineer()
        self._compiled_rules = {
            WazuhFamilyFeatureEngineer.FAMILY_WEB_ACCESS: self._compile_rules(self.WEB_ACCESS_RULES),
            WazuhFamilyFeatureEngineer.FAMILY_AUTH: self._compile_rules(self.AUTH_RULES),
            WazuhFamilyFeatureEngineer.FAMILY_HOST: self._compile_rules(self.HOST_RULES),
            WazuhFamilyFeatureEngineer.FAMILY_INTEGRITY: self._compile_rules(self.INTEGRITY_RULES),
        }

    def build(
        self,
        logs: Sequence[Dict[str, Any]],
        model_family: str,
        *,
        reason: str = "bootstrap_seed_dataset",
        min_class_support: int = 10,
        preview_limit: int = 100,
        include_feedback_overrides: bool = True,
    ) -> Dict[str, Any]:
        normalized_family = self._normalize_family(model_family)
        schema_version = self._required_schema(normalized_family)
        staged_rows: List[Dict[str, Any]] = []
        raw_label_counts: Counter[str] = Counter()
        usable_samples = 0
        skipped_logs = 0
        feedback_override_count = 0
        seen_keys: set[str] = set()

        for log in logs:
            dedupe_key = self._dedupe_key(log)
            if dedupe_key in seen_keys:
                continue
            seen_keys.add(dedupe_key)

            family = self._family_for_log(log)
            if family != normalized_family:
                skipped_logs += 1
                continue

            sample = self._sample_for_log(log, normalized_family, schema_version)
            if sample is None:
                skipped_logs += 1
                continue

            usable_samples += 1
            heuristic_verdict, heuristic_classification, heuristic_reason = self._heuristic_label(log, normalized_family)
            feedback_override = self._feedback_override(log) if include_feedback_overrides else None
            effective_verdict = heuristic_verdict
            effective_classification = heuristic_classification
            label_source = "heuristic"
            if feedback_override:
                effective_verdict = feedback_override["verdict"]
                effective_classification = feedback_override["classification"]
                label_source = str(feedback_override["label_source"])
                feedback_override_count += 1

            raw_label = effective_classification or "BENIGN"
            if raw_label != "BENIGN":
                raw_label_counts[raw_label] += 1

            staged_rows.append(
                {
                    "log_id": str(log.get("_id") or ""),
                    "timestamp": self._timestamp_string(log),
                    "decoder_name": self._decoder_name(log),
                    "message": self._review_message(log),
                    "sample": sample,
                    "heuristic_verdict": heuristic_verdict,
                    "heuristic_classification": heuristic_classification,
                    "heuristic_reason": heuristic_reason,
                    "review_verdict": effective_verdict,
                    "review_classification": effective_classification,
                    "label_source": label_source,
                }
            )

        label_to_id: Dict[str, int] = {"BENIGN": 0}
        label_distribution: Counter[str] = Counter()
        raw_distribution: Counter[str] = Counter()
        verdict_distribution: Counter[str] = Counter()
        training_samples: List[Dict[str, Any]] = []
        labels: List[int] = []
        timestamps: List[str] = []

        training_rows = sorted(staged_rows, key=lambda row: row["timestamp"])
        preview_rows = sorted(staged_rows, key=lambda row: row["timestamp"], reverse=True)[:preview_limit]

        for row in training_rows:
            raw_label = row["review_classification"] or "BENIGN"
            normalized_label = self._normalize_attack_label(
                normalized_family,
                raw_label,
                raw_label_counts,
                min_class_support,
            )
            raw_distribution[raw_label] += 1
            label_distribution[normalized_label] += 1
            verdict_distribution[row["review_verdict"]] += 1
            label_to_id.setdefault(normalized_label, len(label_to_id))
            training_samples.append(row["sample"])
            labels.append(label_to_id[normalized_label])
            timestamps.append(row["timestamp"])

        benign_count = int(label_distribution.get("BENIGN", 0))
        attack_count = int(sum(count for label, count in label_distribution.items() if label != "BENIGN"))
        return {
            "model_family": normalized_family,
            "feature_schema_version": schema_version,
            "scanned_logs": len(logs),
            "usable_samples": usable_samples,
            "skipped_logs": skipped_logs,
            "feedback_override_count": feedback_override_count,
            "label_distribution": dict(sorted(label_distribution.items())),
            "raw_label_distribution": dict(sorted(raw_distribution.items())),
            "verdict_distribution": dict(sorted(verdict_distribution.items())),
            "thresholds": {
                "benign_required": 1000,
                "attack_required": 200,
                "benign_available": benign_count,
                "attack_available": attack_count,
                "passed": benign_count >= 1000 and attack_count >= 200,
            },
            "rows": [self._serialize_preview_row(row) for row in preview_rows],
            "training_payload": {
                "reason": reason,
                "model_family": normalized_family,
                "feature_schema_version": schema_version,
                "samples": training_samples,
                "labels": labels,
                "timestamps": timestamps,
                "label_map": {str(label_id): label_name for label_name, label_id in label_to_id.items()},
            },
        }

    def classify_log(
        self,
        log: Dict[str, Any],
        *,
        include_feedback_overrides: bool = True,
    ) -> Dict[str, Any]:
        family = self._family_for_log(log)
        if not family:
            return {
                "model_family": None,
                "feature_schema_version": None,
                "alert_type": "benign",
                "classification": None,
                "review_verdict": "confirmed_benign",
                "reason": "unsupported_decoder_family",
                "label_source": "rules_fallback",
            }

        schema_version = self._required_schema(family)
        heuristic_verdict, heuristic_classification, heuristic_reason = self._heuristic_label(log, family)
        effective_verdict = heuristic_verdict
        effective_classification = heuristic_classification
        label_source = "heuristic"
        if include_feedback_overrides:
            feedback_override = self._feedback_override(log)
            if feedback_override:
                effective_verdict = feedback_override["verdict"]
                effective_classification = feedback_override["classification"]
                label_source = str(feedback_override["label_source"])

        alert_type = "known_attack" if effective_verdict == "confirmed_known_attack" and effective_classification else "benign"
        return {
            "model_family": family,
            "feature_schema_version": schema_version,
            "alert_type": alert_type,
            "classification": effective_classification if alert_type == "known_attack" else None,
            "review_verdict": effective_verdict,
            "reason": heuristic_reason,
            "label_source": label_source,
        }

    @staticmethod
    def _compile_rules(rules: Iterable[Tuple[str, List[str]]]) -> List[Tuple[str, List[re.Pattern[str]]]]:
        return [(label, [re.compile(pattern, re.IGNORECASE) for pattern in patterns]) for label, patterns in rules]

    def _normalize_family(self, model_family: str) -> str:
        normalized = str(model_family or "").strip().lower()
        if normalized not in self._engineer.SCHEMA_BY_FAMILY:
            supported = ", ".join(sorted(self._engineer.SCHEMA_BY_FAMILY))
            raise ValueError(f"Unsupported model family '{model_family}'. Supported families: {supported}")
        return normalized

    def _required_schema(self, model_family: str) -> str:
        schema = self._engineer.schema_for_family(model_family)
        if not schema:
            raise ValueError(f"No schema configured for model family {model_family}")
        return schema

    def _family_for_log(self, log: Dict[str, Any]) -> Optional[str]:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict):
            family = metadata.get("model_family")
            if isinstance(family, str) and family.strip():
                return family.strip().lower()
        payload = self._raw_payload(log)
        if payload is None:
            return None
        return self._engineer.family_for_payload(payload)

    def _sample_for_log(
        self,
        log: Dict[str, Any],
        model_family: str,
        schema_version: str,
    ) -> Optional[Dict[str, Any]]:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict):
            features = metadata.get("engineered_features")
            if isinstance(features, dict) and isinstance(features.get(schema_version), dict):
                return features[schema_version]

        payload = self._raw_payload(log)
        if payload is None:
            return None
        engineered = self._engineer.engineer_payload(payload, message_override=self._preferred_message(log, payload))
        if engineered.get("model_family") != model_family:
            return None
        nested = engineered.get("engineered_features") or {}
        sample = nested.get(schema_version)
        if isinstance(sample, dict):
            return sample
        return None

    def _heuristic_label(self, log: Dict[str, Any], model_family: str) -> Tuple[str, Optional[str], str]:
        if model_family == WazuhFamilyFeatureEngineer.FAMILY_WEB_ACCESS:
            return self._heuristic_web_access(log)
        if model_family == WazuhFamilyFeatureEngineer.FAMILY_AUTH:
            return self._heuristic_auth(log)
        if model_family == WazuhFamilyFeatureEngineer.FAMILY_HOST:
            return self._heuristic_host(log)
        return self._heuristic_integrity(log)

    def _heuristic_web_access(self, log: Dict[str, Any]) -> Tuple[str, Optional[str], str]:
        payload = self._raw_payload(log) or {}
        message = self._preferred_message(log, payload)
        metadata = log.get("metadata") or {}
        features = metadata.get("engineered_features") if isinstance(metadata, dict) else None
        path = ""
        method = ""
        if isinstance(features, dict):
            sample = features.get(self._engineer.SCHEMA_BY_FAMILY[WazuhFamilyFeatureEngineer.FAMILY_WEB_ACCESS])
            if isinstance(sample, dict):
                categorical = sample.get("categorical") or {}
                text = sample.get("text") or {}
                if isinstance(categorical, dict):
                    method = str(categorical.get("method") or "").upper()
                if isinstance(text, dict):
                    path = str(text.get("path") or "")

        parsed_method, parsed_path = self._parse_request_line(message)
        method = method or parsed_method
        path = path or parsed_path
        rule_text = f"{method} {path}"
        for label, patterns in self._compiled_rules[WazuhFamilyFeatureEngineer.FAMILY_WEB_ACCESS]:
            for pattern in patterns:
                if pattern.search(rule_text):
                    return ("confirmed_known_attack", label, pattern.pattern)
        return ("confirmed_benign", None, "")

    def _heuristic_auth(self, log: Dict[str, Any]) -> Tuple[str, Optional[str], str]:
        payload = self._raw_payload(log) or {}
        message = str(log.get("message") or "").lower()
        decoder = self._decoder_name(log)
        level = self._rule_level(payload)
        for label, patterns in self._compiled_rules[WazuhFamilyFeatureEngineer.FAMILY_AUTH]:
            for pattern in patterns:
                if pattern.search(message):
                    return ("confirmed_known_attack", label, pattern.pattern)
        if decoder == "sudo" and level >= 10 and "authentication failure" in message:
            return ("confirmed_known_attack", "SUDO_POLICY_VIOLATION", "sudo_authentication_failure_high_level")
        if decoder in {"pam", "sshd"} and level >= 12 and "failed password" in message:
            return ("confirmed_known_attack", "AUTH_BRUTE_FORCE", "failed_password_high_level")
        return ("confirmed_benign", None, "")

    def _heuristic_host(self, log: Dict[str, Any]) -> Tuple[str, Optional[str], str]:
        message = str(log.get("message") or "").lower()
        for label, patterns in self._compiled_rules[WazuhFamilyFeatureEngineer.FAMILY_HOST]:
            for pattern in patterns:
                if pattern.search(message):
                    return ("confirmed_known_attack", label, pattern.pattern)
        return ("confirmed_benign", None, "")

    def _heuristic_integrity(self, log: Dict[str, Any]) -> Tuple[str, Optional[str], str]:
        message = str(log.get("message") or "").lower()
        payload = self._raw_payload(log) or {}
        decoder = self._decoder_name(log)
        for label, patterns in self._compiled_rules[WazuhFamilyFeatureEngineer.FAMILY_INTEGRITY]:
            for pattern in patterns:
                if pattern.search(message):
                    return ("confirmed_known_attack", label, pattern.pattern)
        if decoder == "rootcheck" and self._rule_level(payload) >= 8:
            return ("confirmed_known_attack", "ROOTCHECK_FINDING", "rootcheck_high_level")
        return ("confirmed_benign", None, "")

    def _feedback_override(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        metadata = log.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        feedback = metadata.get("feedback")
        if not isinstance(feedback, dict):
            return None
        verdict = str(feedback.get("verdict") or "").strip().lower()
        if verdict in {"false_positive", "confirmed_benign"}:
            return {
                "verdict": verdict,
                "classification": None,
                "label_source": f"feedback_{verdict}",
            }
        if verdict != "confirmed_known_attack":
            return None
        manual_promotion = metadata.get("manual_promotion")
        classification = ""
        if isinstance(manual_promotion, dict):
            classification = str(manual_promotion.get("classification") or "").strip()
        if not classification:
            classification = str((((log.get("ml_result") or {}).get("classification")) or "")).strip()
        if not classification:
            return None
        return {
            "verdict": "confirmed_known_attack",
            "classification": MLPromotionService.validate_label(
                MLPromotionService.normalize_classification_label(classification)
            ),
            "label_source": "feedback_confirmed_known_attack",
        }

    def _normalize_attack_label(
        self,
        model_family: str,
        label_name: str,
        label_counts: Counter[str],
        min_class_support: int,
    ) -> str:
        if label_name == "BENIGN":
            return label_name
        if int(label_counts.get(label_name, 0)) < min_class_support:
            return self.GENERIC_ATTACK_LABEL_BY_FAMILY[model_family]
        return label_name

    @staticmethod
    def _serialize_preview_row(row: Dict[str, Any]) -> Dict[str, Any]:
        classification = row["review_classification"]
        return {
            "log_id": row["log_id"],
            "timestamp": row["timestamp"],
            "decoder_name": row["decoder_name"],
            "message": row["message"],
            "heuristic_verdict": row["heuristic_verdict"],
            "heuristic_classification": row["heuristic_classification"],
            "heuristic_reason": row["heuristic_reason"],
            "review_verdict": row["review_verdict"],
            "review_classification": classification,
            "label_source": row["label_source"],
        }

    @staticmethod
    def _timestamp_string(log: Dict[str, Any]) -> str:
        timestamp = log.get("timestamp")
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()
        return str(timestamp or "")

    @staticmethod
    def _dedupe_key(log: Dict[str, Any]) -> str:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict):
            ingest_key = metadata.get("raw_ingest_key")
            if isinstance(ingest_key, str) and ingest_key.strip():
                return ingest_key.strip()
        if log.get("_id"):
            return str(log["_id"])
        return f"row:{id(log)}"

    @staticmethod
    def _raw_payload(log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        metadata = log.get("metadata") or {}
        if isinstance(metadata, dict):
            payload = metadata.get("raw_wazuh_payload")
            if isinstance(payload, dict):
                return payload
        payload = log.get("payload")
        if isinstance(payload, dict):
            return payload
        return None

    def _decoder_name(self, log: Dict[str, Any]) -> str:
        payload = self._raw_payload(log)
        if not payload:
            return ""
        decoder = payload.get("decoder")
        if isinstance(decoder, dict):
            return str(decoder.get("name") or "").strip().lower()
        return ""

    @staticmethod
    def _rule_level(payload: Dict[str, Any]) -> int:
        rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
        try:
            return int(rule.get("level", 0) or 0)
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _parse_request_line(message: str) -> Tuple[str, str]:
        match = _HTTP_REQUEST_RE.match(message)
        if not match:
            return "", ""
        method = str(match.group("method") or "").upper()
        path = str(match.group("path") or "")
        parsed = urlparse(path)
        return method, parsed.path or path

    def _review_message(self, log: Dict[str, Any]) -> str:
        payload = self._raw_payload(log)
        message = self._preferred_message(log, payload)
        return str(message or "")[:1000]

    @staticmethod
    def _preferred_message(log: Dict[str, Any], payload: Optional[Dict[str, Any]]) -> str:
        if isinstance(payload, dict):
            full_log = str(payload.get("full_log") or "").strip()
            if full_log:
                return full_log
            description = str((payload.get("rule") or {}).get("description") or "").strip()
            if description:
                return description
        return str(log.get("message") or "")
