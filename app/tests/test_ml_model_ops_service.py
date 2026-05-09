import asyncio
from datetime import datetime, timedelta

from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer
from app.services.ml_model_ops_service import MLModelOpsService


class _FakeLogsRepo:
    def __init__(self) -> None:
        self._rows = {
            "fp1": {
                "_id": "fp1",
                "timestamp": datetime(2026, 1, 1, 0, 0, 2),
                "metadata": {
                    "raw_ingest_key": "fp1",
                    "model_family": "web_access",
                    "feature_schema_version": "web_access_v1",
                    "engineered_features": {
                        "web_access_v1": {
                            "numeric": {"status_code": 200.0},
                            "categorical": {"method": "GET"},
                            "text": {"path": "/"},
                        }
                    },
                },
            },
        }
        for idx in range(200):
            key = f"k{idx}"
            self._rows[key] = {
                "_id": key,
                "timestamp": datetime(2026, 1, 1, 0, 0, 3) + timedelta(seconds=idx),
                "metadata": {
                    "raw_ingest_key": key,
                    "model_family": "web_access",
                    "feature_schema_version": "web_access_v1",
                    "engineered_features": {
                        "web_access_v1": {
                            "numeric": {"status_code": 404.0},
                            "categorical": {"method": "GET"},
                            "text": {"path": f"/probe/{idx}"},
                        }
                    },
                },
                "ml_result": {"classification": "PORTSCAN"},
            }
        for idx in range(1000):
            key = f"b{idx}"
            self._rows[key] = {
                "_id": key,
                "timestamp": datetime(2026, 1, 1, 1, 0, idx % 60),
                "metadata": {
                    "raw_ingest_key": key,
                    "model_family": "web_access",
                    "feature_schema_version": "web_access_v1",
                    "engineered_features": {
                        "web_access_v1": {
                            "numeric": {"status_code": 200.0},
                            "categorical": {"method": "GET"},
                            "text": {"path": f"/asset/{idx}.js"},
                        }
                    },
                },
                "ml_result": {"alert_type": "benign"},
            }

    async def list_logs_by_ids(self, ids):
        return [self._rows[i] for i in ids if i in self._rows]

    async def list_family_benign_logs(self, model_family: str, limit: int):
        assert model_family == "web_access"
        rows = [row for row in self._rows.values() if row.get("metadata", {}).get("model_family") == model_family and row.get("ml_result", {}).get("alert_type") == "benign"]
        return rows[:limit]


def test_build_dataset_uses_feedback_sets_and_excludes_fp_from_attack_labels() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._logs = _FakeLogsRepo()
    service._engineer = WazuhFamilyFeatureEngineer()

    confirmed_known = [{"log_id": f"k{idx}", "classification": "PORTSCAN"} for idx in range(200)]

    async def fake_fetch_feedback_sets(_model_family: str):
        return {
            "confirmed_known": confirmed_known,
            "benign_feedback_log_ids": {"fp1"},
        }

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]
    dataset = asyncio.run(service._build_feedback_dataset("web_access"))

    assert dataset["label_map"]["0"] == "BENIGN"
    assert "PORTSCAN" in set(dataset["label_map"].values())
    assert dataset["model_family"] == "web_access"
    assert dataset["feature_schema_version"] == "web_access_v1"
    assert len(dataset["samples"]) >= 1002
    assert dataset["labels"].count(0) >= 1001
    assert dataset["labels"].count(1) == 200
