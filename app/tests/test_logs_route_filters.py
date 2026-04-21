from datetime import datetime

from app.routes.logs import _build_log_filters


def test_build_log_filters_includes_agent_and_origin_clauses() -> None:
    filters = _build_log_filters(
        source=None,
        severity=None,
        agent="prod-web",
        origin="/var/log",
        source_app=None,
        channel=None,
        start_ts=None,
        end_ts=None,
    )

    assert "$and" in filters
    clauses = filters["$and"]
    assert any("metadata.agent.name" in branch for clause in clauses for branch in clause.get("$or", []))
    assert any("metadata.location" in branch for clause in clauses for branch in clause.get("$or", []))


def test_build_log_filters_preserves_existing_time_and_source_filters() -> None:
    start_ts = datetime(2026, 4, 20, 0, 0, 0)
    end_ts = datetime(2026, 4, 21, 0, 0, 0)
    filters = _build_log_filters(
        source="wazuh",
        severity="high",
        agent=None,
        origin=None,
        source_app=None,
        channel=None,
        start_ts=start_ts,
        end_ts=end_ts,
    )

    assert "$and" in filters
    clauses = filters["$and"]
    assert {"severity": "high"} in clauses
    assert any("source" in clause for clause in clauses)
    assert any(clause.get("timestamp", {}).get("$gte") == start_ts for clause in clauses if "timestamp" in clause)
    assert any(clause.get("timestamp", {}).get("$lte") == end_ts for clause in clauses if "timestamp" in clause)


def test_build_log_filters_supports_source_app_and_channel() -> None:
    filters = _build_log_filters(
        source=None,
        severity=None,
        agent=None,
        origin=None,
        source_app="Authentication",
        channel="Network",
        start_ts=None,
        end_ts=None,
    )

    assert "$and" in filters
    rendered = str(filters)
    assert "metadata.location" in rendered
    assert "metadata.raw_wazuh_payload.data.srcip" in rendered


def test_build_log_filters_supports_general_channel() -> None:
    filters = _build_log_filters(
        source=None,
        severity=None,
        agent=None,
        origin=None,
        source_app=None,
        channel="General",
        start_ts=None,
        end_ts=None,
    )

    rendered = str(filters)
    assert "metadata.raw_wazuh_payload.data.srcip" in rendered
    assert "sshd|syscheck|kernel" in rendered
