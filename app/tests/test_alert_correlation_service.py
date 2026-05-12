from app.services.alert_service import (
    ANOMALY_CLASSIFICATION_SENTINEL,
    MISSING_IP_SENTINEL,
    AlertService,
)


def test_correlation_key_includes_type_and_ips() -> None:
    key = AlertService._build_correlation_key(
        alert_type="known_attack",
        classification="SSH_BRUTE",
        source_ip="203.0.113.10",
        destination_ip="10.0.0.5",
    )
    assert key == "known_attack|ssh_brute|203.0.113.10|10.0.0.5"


def test_correlation_key_uses_anomaly_and_missing_ip_sentinels() -> None:
    key = AlertService._build_correlation_key(
        alert_type="anomaly",
        classification="",
        source_ip="",
        destination_ip="",
    )
    assert key == f"anomaly|{ANOMALY_CLASSIFICATION_SENTINEL}|{MISSING_IP_SENTINEL}|{MISSING_IP_SENTINEL}"

