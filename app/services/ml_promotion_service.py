import hashlib
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from app.db.repositories.promotion_repository import PromotionRepository
from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer


_KNOWN_ATTACK_LABELS = {
    "PORTSCAN",
    "SQL_INJECTION_ATTEMPT",
    "SSH_BRUTE",
    "CREDENTIAL_ATTACK",
    "MALWARE_DETECTED",
    "RCE_ATTEMPT",
    "DIRECTORY_TRAVERSAL",
    "XSS_ATTEMPT",
}


def _normalize_path(path: str) -> str:
    cleaned = re.sub(r"/+", "/", path.strip())
    return cleaned[:200]


def _user_agent_family(user_agent: str) -> str:
    probe = user_agent.lower()
    if "nmap scripting engine" in probe:
        return "nmap"
    if "sqlmap" in probe:
        return "sqlmap"
    if "nikto" in probe:
        return "nikto"
    if "mozilla" in probe:
        return "browser"
    if "curl" in probe:
        return "curl"
    return "other"


def _parse_access_log_fields(message: str) -> Dict[str, str]:
    pattern = re.compile(
        r'^(?P<srcip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)[^"]*"\s+\d{3}\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
    )
    match = pattern.match(message.strip())
    if not match:
        return {"srcip": "", "method": "", "path": "", "ua": ""}
    return {
        "srcip": match.group("srcip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "ua": match.group("ua"),
    }


class MLPromotionService:
    def __init__(self) -> None:
        self._repo = PromotionRepository()

    @staticmethod
    def normalize_classification_label(label: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9_]+", "_", str(label or "").strip().upper()).strip("_")
        if not normalized:
            raise ValueError("classification label is required")
        return normalized[:64]

    @staticmethod
    def validate_label(normalized_label: str) -> str:
        if normalized_label in _KNOWN_ATTACK_LABELS:
            return normalized_label
        # Allow custom labels, but keep clear taxonomy.
        return normalized_label

    @staticmethod
    def fingerprint_for_log(log_doc: Dict[str, Any]) -> Optional[str]:
        metadata = log_doc.get("metadata") or {}
        if not isinstance(metadata, dict):
            return None
        engineer = WazuhFamilyFeatureEngineer()
        structured = engineer.build_prediction_payload(log_doc)
        if structured:
            family = str(structured.get("model_family") or "").strip().lower()
            sample = structured.get("sample")
            if isinstance(sample, dict):
                fingerprint = MLPromotionService._family_fingerprint(family, sample)
                if fingerprint:
                    return fingerprint

        raw = metadata.get("raw_wazuh_payload")
        if not isinstance(raw, dict):
            return None

        decoder = raw.get("decoder") if isinstance(raw.get("decoder"), dict) else {}
        decoder_name = str(decoder.get("name") or "").strip().lower()
        if decoder_name != "web-accesslog":
            return None

        parsed = _parse_access_log_fields(str(log_doc.get("message") or ""))
        srcip = parsed["srcip"] or str((raw.get("data") or {}).get("srcip") or "")
        method = parsed["method"]
        path_raw = parsed["path"]
        ua = parsed["ua"]
        if path_raw:
            path = _normalize_path(urlsplit(path_raw).path or path_raw)
        else:
            path = ""

        family = _user_agent_family(ua)
        base = f"{decoder_name}|{srcip}|{method}|{path}|{family}"
        if not base.strip("|"):
            return None
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    @staticmethod
    def _family_fingerprint(model_family: str, sample: Dict[str, Any]) -> Optional[str]:
        numeric = sample.get("numeric") if isinstance(sample.get("numeric"), dict) else {}
        categorical = sample.get("categorical") if isinstance(sample.get("categorical"), dict) else {}
        text = sample.get("text") if isinstance(sample.get("text"), dict) else {}

        base = ""
        if model_family == WazuhFamilyFeatureEngineer.FAMILY_WEB_ACCESS:
            base = "|".join(
                [
                    model_family,
                    str(categorical.get("host_ip") or ""),
                    str(categorical.get("method") or ""),
                    str(categorical.get("route_template") or ""),
                    str(categorical.get("user_agent_family") or ""),
                ]
            )
        elif model_family == WazuhFamilyFeatureEngineer.FAMILY_AUTH:
            base = "|".join(
                [
                    model_family,
                    str(categorical.get("agent_name") or ""),
                    str(categorical.get("decoder_name") or ""),
                    str(categorical.get("action") or ""),
                    str(categorical.get("result") or ""),
                    str(categorical.get("account") or ""),
                    str(categorical.get("source_ip") or ""),
                ]
            )
        elif model_family == WazuhFamilyFeatureEngineer.FAMILY_HOST:
            base = "|".join(
                [
                    model_family,
                    str(categorical.get("agent_name") or ""),
                    str(categorical.get("decoder_name") or ""),
                    str(categorical.get("rule_id") or ""),
                    str(categorical.get("program_name") or ""),
                    str(categorical.get("severity") or ""),
                    str(text.get("title") or ""),
                ]
            )
        elif model_family == WazuhFamilyFeatureEngineer.FAMILY_INTEGRITY:
            base = "|".join(
                [
                    model_family,
                    str(categorical.get("agent_name") or ""),
                    str(categorical.get("decoder_name") or ""),
                    str(categorical.get("rule_id") or ""),
                    str(categorical.get("result") or ""),
                    str(categorical.get("target") or ""),
                    str(numeric.get("is_failed_result") or ""),
                ]
            )

        if not base or not base.strip("|"):
            return None
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    async def register_manual_promotion(
        self,
        log_doc: Dict[str, Any],
        classification: str,
        created_by: str,
        notes: Optional[str] = None,
    ) -> str:
        fingerprint = self.fingerprint_for_log(log_doc)
        if not fingerprint:
            raise ValueError("Cannot build fingerprint for this log")
        normalized = self.validate_label(self.normalize_classification_label(classification))
        await self._repo.upsert_promotion(
            fingerprint=fingerprint,
            classification=normalized,
            created_by=created_by,
            notes=notes,
        )
        return fingerprint

    async def resolve_manual_promotion(self, log_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fingerprint = self.fingerprint_for_log(log_doc)
        if not fingerprint:
            return None
        found = await self._repo.find_active(fingerprint)
        if not found:
            return None
        return {
            "fingerprint": fingerprint,
            "classification": found.get("classification"),
        }
