from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer


def test_engineer_web_access_payload_creates_structured_family_features() -> None:
    engineer = WazuhFamilyFeatureEngineer()
    payload = {
        "timestamp": "2026-05-08T19:15:04.743+0500",
        "agent": {"name": "kali"},
        "decoder": {"name": "web-accesslog"},
        "location": "/var/log/nginx/access.log",
        "rule": {"level": 10},
        "full_log": '192.168.56.102 - - [08/May/2026:22:38:41 +0500] "GET /rest/products/search?q=test HTTP/1.1" 200 3921 "-" "Mozilla/5.0 Firefox/140.0"',
    }

    result = engineer.engineer_payload(payload)

    assert result["model_family"] == "web_access"
    assert result["feature_schema_version"] == "web_access_v1"
    sample = result["engineered_features"]["web_access_v1"]
    assert sample["numeric"]["status_code"] == 200.0
    assert sample["numeric"]["query_param_count"] == 1.0
    assert sample["categorical"]["method"] == "GET"
    assert sample["categorical"]["user_agent_family"] == "firefox"


def test_engineer_auth_payload_routes_to_auth_family() -> None:
    engineer = WazuhFamilyFeatureEngineer()
    payload = {
        "timestamp": "2026-05-08T19:15:04.743+0500",
        "agent": {"name": "bigboss"},
        "decoder": {"name": "pam"},
        "location": "/var/log/auth.log",
        "rule": {"level": 8},
        "full_log": "pam_unix(sshd:auth): authentication failure; user=root rhost=192.168.56.1",
    }

    result = engineer.engineer_payload(payload)

    assert result["model_family"] == "auth"
    sample = result["engineered_features"]["auth_v1"]
    assert sample["categorical"]["action"] == "ssh"
    assert sample["categorical"]["result"] == "failure"
    assert sample["numeric"]["is_failure"] == 1.0


def test_build_prediction_payload_reuses_stored_engineered_features() -> None:
    engineer = WazuhFamilyFeatureEngineer()
    log = {
        "metadata": {
            "model_family": "web_access",
            "feature_schema_version": "web_access_v1",
            "engineered_features": {
                "web_access_v1": {
                    "numeric": {"status_code": 200.0},
                    "categorical": {"method": "GET"},
                    "text": {"path": "/"},
                }
            },
            "raw_wazuh_payload": {"decoder": {"name": "web-accesslog"}},
        }
    }

    payload = engineer.build_prediction_payload(log)

    assert payload == {
        "model_family": "web_access",
        "feature_schema_version": "web_access_v1",
        "sample": {
            "numeric": {"status_code": 200.0},
            "categorical": {"method": "GET"},
            "text": {"path": "/"},
        },
    }


def test_engineer_web_access_payload_detects_nmap_user_agent_family() -> None:
    engineer = WazuhFamilyFeatureEngineer()
    payload = {
        "timestamp": "2026-05-08T19:15:04.743+0500",
        "agent": {"name": "kali"},
        "decoder": {"name": "web-accesslog"},
        "location": "/var/log/nginx/access.log",
        "rule": {"level": 10},
        "full_log": '127.0.0.1 - - [08/May/2026:22:39:11 +0500] "OPTIONS / HTTP/1.1" 204 0 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"',
    }

    result = engineer.engineer_payload(payload)

    assert result["engineered_features"]["web_access_v1"]["categorical"]["user_agent_family"] == "nmap"


def test_build_prediction_payload_prefers_full_log_over_lossy_message() -> None:
    engineer = WazuhFamilyFeatureEngineer()
    log = {
        "message": "GET request received.",
        "metadata": {
            "raw_wazuh_payload": {
                "decoder": {"name": "web-accesslog"},
                "rule": {"level": 10, "description": "GET request received."},
                "full_log": '127.0.0.1 - - [08/May/2026:22:39:11 +0500] "GET /.git/HEAD HTTP/1.1" 200 75055 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"',
            }
        },
    }

    payload = engineer.build_prediction_payload(log)

    assert payload is not None
    assert payload["sample"]["categorical"]["user_agent_family"] == "nmap"
    assert payload["sample"]["text"]["path"] == "/.git/HEAD"
