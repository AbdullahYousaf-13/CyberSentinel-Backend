import asyncio

from app.services.ml_model_ops_service import MLModelOpsService


class _FakeLogsRepo:
    def __init__(self) -> None:
        self._rows = {
            "k1": {
                "_id": "k1",
                "metadata": {"engineered_features_78": {"f1": 1.0, "f2": 2.0}},
                "ml_result": {"classification": "PORTSCAN"},
            },
            "fp1": {
                "_id": "fp1",
                "metadata": {"engineered_features_78": {"f1": 0.5, "f2": 0.1}},
            },
            "b1": {
                "_id": "b1",
                "metadata": {"engineered_features_78": {"f1": 0.0, "f2": 0.0}},
            },
        }

    async def list_logs_by_ids(self, ids):
        return [self._rows[i] for i in ids if i in self._rows]

    async def list_web_benign_logs(self, limit: int):
        rows = [self._rows["fp1"], self._rows["b1"]]
        return rows[:limit]


class _FakeBuilder:
    def build(self, raw_file_path: str, min_samples_per_class: int = 50):
        assert raw_file_path.endswith(".json")
        assert min_samples_per_class == 50
        return {
            "reason": "wazuh_bootstrap_retrain",
            "features": [[1.0, 2.0], [0.1, 0.0]],
            "labels": [1, 0],
            "feature_names": ["f1", "f2"],
            "feature_schema": "wazuh_native_v1",
            "label_map": {"0": "BENIGN", "1": "NMAP_BASIC_SCAN", "2": "OTHER_ATTACK"},
            "report": {},
        }


def test_build_dataset_bootstrap_and_feedback_augmentation() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type("S", (), {"raw_wazuh_training_path": "C:/tmp/raw.json", "min_samples_per_attack_class": 50})()
    service._logs = _FakeLogsRepo()
    service._dataset_builder = _FakeBuilder()

    confirmed_known = [{"log_id": "k1", "classification": "nmap_basic_scan"}]

    async def fake_fetch_feedback_sets():
        return {
            "confirmed_known": confirmed_known,
            "false_positive_log_ids": {"fp1"},
        }

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]

    dataset = asyncio.run(MLModelOpsService._build_dataset(service))

    assert dataset["label_map"]["0"] == "BENIGN"
    assert len(dataset["features"]) == 4
    assert dataset["labels"].count(0) >= 2
