from datetime import datetime

from app.ml.bootstrap import WazuhBootstrapDatasetBuilder
from app.services.ml_promotion_service import MLPromotionService


def _web_log(
    log_id: str,
    path: str,
    verdict: str | None = None,
    classification: str | None = None,
    message_override: str | None = None,
):
    full_log = f'10.0.0.5 - - [01/Jan/2026:00:00:00 +0000] "GET {path} HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    metadata = {
        "raw_ingest_key": log_id,
        "model_family": "web_access",
        "feature_schema_version": "web_access_v1",
        "engineered_features": {
            "web_access_v1": {
                "numeric": {"status_code": 200.0},
                "categorical": {
                    "method": "GET",
                    "route_template": path,
                    "user_agent_family": "chrome",
                    "host_ip": "10.0.0.5",
                },
                "text": {"path": path, "query": "", "user_agent": "Mozilla"},
            }
        },
        "raw_wazuh_payload": {
            "timestamp": "2026-01-01T00:00:00Z",
            "decoder": {"name": "web-accesslog"},
            "rule": {"level": 3},
            "full_log": full_log,
        },
    }
    if verdict:
        metadata["feedback"] = {"verdict": verdict}
    if classification:
        metadata["manual_promotion"] = {"classification": classification}
    return {
        "_id": log_id,
        "timestamp": datetime(2026, 1, 1, 0, 0, 0),
        "message": message_override if message_override is not None else full_log,
        "metadata": metadata,
    }


def _auth_log(log_id: str, message: str):
    return {
        "_id": log_id,
        "timestamp": datetime(2026, 1, 1, 0, 0, 0),
        "message": message,
        "metadata": {
            "raw_ingest_key": log_id,
            "model_family": "auth",
            "feature_schema_version": "auth_v1",
            "engineered_features": {
                "auth_v1": {
                    "numeric": {"rule_level": 12.0},
                    "categorical": {
                        "agent_name": "agent-1",
                        "decoder_name": "pam",
                        "action": "ssh",
                        "result": "failure",
                        "account": "root",
                        "source_ip": "192.168.1.10",
                    },
                    "text": {"message": message, "title": ""},
                }
            },
            "raw_wazuh_payload": {
                "timestamp": "2026-01-01T00:00:00Z",
                "decoder": {"name": "pam"},
                "rule": {"level": 12},
            },
        },
    }


def test_builder_applies_feedback_override_and_collapses_low_support_labels() -> None:
    builder = WazuhBootstrapDatasetBuilder()
    rows = [
        _web_log("a1", "/../../etc/passwd"),
        _web_log("a2", "/wp-login.php"),
        _web_log("b1", "/rest/products/search", verdict="confirmed_benign"),
    ]

    built = builder.build(
        rows,
        "web_access",
        reason="test",
        min_class_support=2,
        preview_limit=10,
        include_feedback_overrides=True,
    )

    assert built["thresholds"]["benign_available"] == 1
    assert built["label_distribution"]["WEB_ATTACK_GENERIC"] == 2
    assert built["feedback_override_count"] == 1
    assert any(row["review_verdict"] == "confirmed_benign" for row in built["rows"])


def test_auth_logs_produce_family_specific_fingerprint() -> None:
    fingerprint = MLPromotionService.fingerprint_for_log(
        _auth_log("auth-1", "pam_unix(sshd:auth): authentication failure for invalid user admin from 192.168.1.10")
    )
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64


def test_builder_prefers_full_log_when_stored_message_is_lossy() -> None:
    builder = WazuhBootstrapDatasetBuilder()
    row = _web_log("lossy-1", "/wp-login.php", message_override="GET request received.")
    built = builder.build([row], "web_access", preview_limit=1, min_class_support=1)

    assert built["label_distribution"]["WORDPRESS_PROBE"] == 1
    assert built["rows"][0]["message"].startswith("10.0.0.5 - - [01/Jan/2026")
