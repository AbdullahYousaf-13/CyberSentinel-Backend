import asyncio
from datetime import datetime, timezone

from bson import ObjectId

from app.routes import alerts as alerts_route
from app.routes.alerts import _build_alert_filters, _build_alert_search_filter


def _search_fields(search_filter: dict) -> set[str]:
    return {next(iter(branch.keys())) for branch in search_filter.get("$or", [])}


def test_alert_search_filter_only_includes_allowed_find_alert_fields() -> None:
    fields = _search_fields(_build_alert_search_filter("127.0.0.1"))

    assert fields == {
        "incident_id",
        "source_ip",
        "metadata.log_summary.source_ip",
        "metadata.log_summary.network.srcip",
        "children.metadata.log_summary.source_ip",
        "children.metadata.log_summary.network.srcip",
        "model_versions_seen",
        "children.model_version",
    }
    assert "severity" not in fields
    assert "alert_type" not in fields
    assert "classification" not in fields
    assert "destination_ip" not in fields
    assert "metadata.log_summary.message" not in fields
    assert "log_ids" not in fields


def test_alert_search_filter_adds_exact_id_for_valid_object_id() -> None:
    alert_id = "64b64c9277f33a3f8c7d0e4a"
    search_filter = _build_alert_search_filter(alert_id)

    assert {"_id": ObjectId(alert_id)} in search_filter["$or"]


def test_build_alert_filters_combines_existing_controls_with_opened_at_and_search() -> None:
    filters = _build_alert_filters(
        severity="high",
        alert_type="known_attack",
        start_ts=datetime(2026, 7, 24, 13, 7, tzinfo=timezone.utc),
        end_ts=datetime(2026, 7, 25, 9, 30, tzinfo=timezone.utc),
        q="20260625181323",
    )

    assert "$and" in filters
    clauses = filters["$and"]
    assert {"severity": {"$in": ["high", "critical"]}} in clauses
    assert {"alert_type": "known_attack"} in clauses
    time_clause = next(clause for clause in clauses if "$or" in clause and any("opened_at" in branch for branch in clause["$or"]))
    assert any(
        branch.get("opened_at", {}).get("$gte") == datetime(2026, 7, 24, 13, 7)
        for branch in time_clause["$or"]
    )
    assert any(
        branch.get("opened_at", {}).get("$lte") == datetime(2026, 7, 25, 9, 30)
        for branch in time_clause["$or"]
    )
    assert any(
        branch.get("metadata.log_summary.event_time", {}).get("$gte") == datetime(2026, 7, 24, 13, 7)
        for branch in time_clause["$or"]
    )
    assert any("model_versions_seen" in branch for clause in clauses for branch in clause.get("$or", []))


def test_count_alerts_route_uses_shared_filter_builder(monkeypatch) -> None:
    class FakeAlertService:
        last_filters = None

        async def count_alerts(self, filters=None):
            FakeAlertService.last_filters = filters
            return 5

    monkeypatch.setattr(alerts_route, "AlertService", FakeAlertService)

    response = asyncio.run(
        alerts_route.count_alerts(
            current_user={"id": "u1"},
            severity="medium",
            alert_type="anomaly",
            start_ts=datetime(2026, 7, 24, 13, 7, tzinfo=timezone.utc),
            end_ts=None,
            q="127.0.0.1",
        )
    )

    assert response == {"count": 5}
    assert FakeAlertService.last_filters == _build_alert_filters(
        severity="medium",
        alert_type="anomaly",
        start_ts=datetime(2026, 7, 24, 13, 7, tzinfo=timezone.utc),
        end_ts=None,
        q="127.0.0.1",
    )
