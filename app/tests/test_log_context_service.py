from datetime import datetime

from app.services.log_context_service import build_normalized_log_context


def test_context_extracts_archive_event_with_rule_and_network() -> None:
    log = {
        "timestamp": datetime(2026, 4, 20, 10, 0, 0),
        "source": "wazuh",
        "message": "fallback message",
        "metadata": {
            "raw_wazuh_payload": {
                "id": "1713607200.100",
                "timestamp": "2026-04-20T10:00:00Z",
                "location": "/var/log/auth.log",
                "rule": {"description": "SSH brute force attempt"},
                "agent": {"name": "prod-web-01"},
                "decoder": {"name": "sshd"},
                "data": {
                    "srcip": "203.0.113.10",
                    "dstip": "10.0.0.5",
                    "srcport": "54421",
                    "dstport": "22",
                    "protocol": "tcp",
                    "action": "denied",
                },
            }
        },
    }

    context = build_normalized_log_context(log)
    assert context["event_id"] == "1713607200.100"
    assert context["agent_name"] == "prod-web-01"
    assert context["event_origin"] == "/var/log/auth.log"
    assert context["decoder_name"] == "sshd"
    assert context["message_normalized"] == "SSH brute force attempt"
    assert context["source_app"] == "Authentication"
    assert context["source_ip"] == "203.0.113.10"
    assert context["destination_ip"] == "10.0.0.5"
    assert context["channel"] == "Network"
    assert context["network"] == {
        "srcip": "203.0.113.10",
        "dstip": "10.0.0.5",
        "srcport": "54421",
        "dstport": "22",
        "protocol": "tcp",
        "action": "denied",
    }


def test_context_handles_archive_event_without_rule() -> None:
    log = {
        "timestamp": datetime(2026, 4, 20, 11, 0, 0),
        "source": "wazuh",
        "message": "kernel event fallback",
        "metadata": {
            "id": "1713610800.200",
            "timestamp": "2026-04-20T11:00:00Z",
            "location": "/var/log/kern.log",
            "decoder": {"name": "kernel"},
        },
    }

    context = build_normalized_log_context(log)
    assert context["event_id"] == "1713610800.200"
    assert context["event_origin"] == "/var/log/kern.log"
    assert context["decoder_name"] == "kernel"
    assert context["message_normalized"] == "kernel event fallback"
    assert context["source_app"] == "System"
    assert context["source_ip"] is None
    assert context["destination_ip"] is None
    assert context["channel"] == "System"


def test_context_handles_event_without_network_fields() -> None:
    log = {
        "timestamp": datetime(2026, 4, 20, 12, 0, 0),
        "source": "wazuh",
        "message": "fim event",
        "metadata": {
            "id": "1713614400.300",
            "timestamp": "2026-04-20T12:00:00Z",
            "decoder": {"name": "syscheck"},
        },
    }

    context = build_normalized_log_context(log)
    assert context["network"] is None
    assert context["decoder_name"] == "syscheck"
    assert context["channel"] == "File"


def test_context_handles_event_without_agent_name() -> None:
    log = {
        "timestamp": datetime(2026, 4, 20, 13, 0, 0),
        "source": "wazuh",
        "message": "manager side event",
        "metadata": {
            "id": "1713618000.400",
            "timestamp": "2026-04-20T13:00:00Z",
            "location": "wazuh-manager",
            "agent": {"id": "001"},
        },
    }

    context = build_normalized_log_context(log)
    assert context["agent_name"] is None
    assert context["event_origin"] == "wazuh-manager"
    assert context["source_app"] == "General System"
    assert context["channel"] == "General"
