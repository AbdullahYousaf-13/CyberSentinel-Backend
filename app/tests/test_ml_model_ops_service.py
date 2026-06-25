import asyncio

import pytest

from app.services.ml_model_ops_service import MLModelOpsService


class _FakeRawRepo:
    def __init__(self, rows=None) -> None:
        self.rows = list(rows or [])
        self.last_limit = None

    async def list_recent_for_retraining(self, limit: int):
        self.last_limit = limit
        return list(self.rows)


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
    def __init__(self, db_dataset=None, file_dataset=None, db_error=None, file_error=None) -> None:
        self.db_dataset = db_dataset or {
            "reason": "wazuh_bootstrap_retrain",
            "features": [[1.0, 2.0], [0.1, 0.0]],
            "labels": [1, 0],
            "feature_names": ["f1", "f2"],
            "feature_schema": "wazuh_native_v1",
            "label_map": {"0": "BENIGN", "1": "NMAP_BASIC_SCAN", "2": "OTHER_ATTACK"},
            "report": {},
        }
        self.file_dataset = file_dataset or {
            "reason": "wazuh_bootstrap_retrain",
            "features": [[2.0, 3.0], [0.2, 0.1]],
            "labels": [1, 0],
            "feature_names": ["f1", "f2"],
            "feature_schema": "wazuh_native_v1",
            "label_map": {"0": "BENIGN", "1": "NMAP_BASIC_SCAN", "2": "OTHER_ATTACK"},
            "report": {},
        }
        self.db_error = db_error
        self.file_error = file_error

    def build_from_rows(self, rows, min_samples_per_class: int = 50):
        assert min_samples_per_class == 50
        if self.db_error:
            raise RuntimeError(self.db_error)
        return {
            **self.db_dataset,
            "report": {**(self.db_dataset.get("report") or {}), "db_rows_seen": len(rows)},
        }

    def build(self, raw_file_path: str, min_samples_per_class: int = 50):
        assert raw_file_path.endswith(".json")
        assert min_samples_per_class == 50
        if self.file_error:
            raise RuntimeError(self.file_error)
        return self.file_dataset


class _FakeJobsRepo:
    def __init__(self, count: int = 0) -> None:
        self.count = count
        self.last_error = None

    async def fail_incomplete_jobs(self, error_message: str) -> int:
        self.last_error = error_message
        return self.count


def test_build_dataset_bootstrap_and_feedback_augmentation() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type(
        "S",
        (),
        {
            "raw_wazuh_training_path": "C:/tmp/raw.json",
            "min_samples_per_attack_class": 50,
            "retrain_raw_wazuh_db_limit": 10000,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(
        rows=[
            {"payload": {"rule": {"description": "normal request"}, "agent": {"name": "sensor"}}},
            {"payload": {"rule": {"description": "scanner detected"}, "agent": {"name": "sensor"}}},
        ]
    )
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
    assert dataset["report"]["source"] == "mongodb"
    assert dataset["report"]["source_row_count"] == 2


def test_build_dataset_falls_back_to_file_when_db_rows_fail() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type(
        "S",
        (),
        {
            "raw_wazuh_training_path": "C:/tmp/raw.json",
            "min_samples_per_attack_class": 50,
            "retrain_raw_wazuh_db_limit": 123,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(rows=[{"payload": {"rule": {"description": "only one row"}}}])
    service._dataset_builder = _FakeBuilder(db_error="Only 1 usable raw Wazuh events found", file_dataset={
        "reason": "wazuh_bootstrap_retrain",
        "features": [[1.0, 2.0], [0.1, 0.0]],
        "labels": [1, 0],
        "feature_names": ["f1", "f2"],
        "feature_schema": "wazuh_native_v1",
        "label_map": {"0": "BENIGN", "1": "NMAP_BASIC_SCAN"},
        "report": {},
    })

    async def fake_fetch_feedback_sets():
        return {"confirmed_known": [], "false_positive_log_ids": set()}

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]

    dataset = asyncio.run(MLModelOpsService._build_dataset(service))

    assert dataset["report"]["source"] == "file_fallback"
    assert service._raw_wazuh_logs.last_limit == 123


def test_build_dataset_raises_clear_error_when_db_and_file_unavailable() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type(
        "S",
        (),
        {
            "raw_wazuh_training_path": "C:/tmp/raw.json",
            "min_samples_per_attack_class": 50,
            "retrain_raw_wazuh_db_limit": 10000,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(rows=[])
    service._dataset_builder = _FakeBuilder(file_error="Raw Wazuh dataset file not found: C:/tmp/raw.json")

    async def fake_fetch_feedback_sets():
        return {"confirmed_known": [], "false_positive_log_ids": set()}

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]

    with pytest.raises(RuntimeError) as exc:
        asyncio.run(MLModelOpsService._build_dataset(service))

    message = str(exc.value)
    assert "No raw Wazuh logs available in database" in message
    assert "Fallback dataset file unavailable" in message


def test_build_dataset_uses_default_db_limit_when_setting_missing() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type(
        "S",
        (),
        {
            "raw_wazuh_training_path": "C:/tmp/raw.json",
            "min_samples_per_attack_class": 50,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(rows=[{"payload": {"rule": {"description": "only one row"}}}])
    service._dataset_builder = _FakeBuilder(db_error="Only 1 usable raw Wazuh events found", file_dataset={
        "reason": "wazuh_bootstrap_retrain",
        "features": [[1.0, 2.0], [0.1, 0.0]],
        "labels": [1, 0],
        "feature_names": ["f1", "f2"],
        "feature_schema": "wazuh_native_v1",
        "label_map": {"0": "BENIGN", "1": "NMAP_BASIC_SCAN"},
        "report": {},
    })

    async def fake_fetch_feedback_sets():
        return {"confirmed_known": [], "false_positive_log_ids": set()}

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]

    asyncio.run(MLModelOpsService._build_dataset(service))

    assert service._raw_wazuh_logs.last_limit == 10000


def test_recover_incomplete_jobs_marks_orphans_failed() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._jobs = _FakeJobsRepo(count=3)

    count = asyncio.run(MLModelOpsService.recover_incomplete_jobs(service))

    assert count == 3
    assert service._jobs.last_error == "Backend restarted before retrain completed"
