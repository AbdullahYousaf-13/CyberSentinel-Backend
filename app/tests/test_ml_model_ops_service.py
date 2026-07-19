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
        self.db_dataset = db_dataset or {}
        self.file_dataset = file_dataset or {}
        self.db_error = db_error
        self.file_error = file_error

    def prepare_rows(self, rows):
        if self.db_error and any("ingest_key" not in row for row in rows):
            raise RuntimeError(self.db_error)
        prepared = []
        for idx, row in enumerate(rows):
            ingest_key = row.get("ingest_key", f"rk{idx}")
            payload = row.get("payload") or {}
            prepared.append(
                {
                    "row": row,
                    "payload": payload,
                    "log": {"metadata": {"raw_wazuh_payload": payload}},
                    "label": str(payload.get("label") or ("nmap_basic_scan" if idx % 2 == 0 else "benign")),
                    "confidence": "high",
                    "raw_ingest_key": ingest_key,
                    "dedup_key": f"ingest:{ingest_key}",
                    "timestamp": payload.get("timestamp", f"2026-05-{idx + 1:02d}T00:00:00Z"),
                }
            )
        return prepared

    def build_from_prepared_rows(self, prepared_rows, min_samples_per_class: int = 50, report=None):
        assert min_samples_per_class == 50
        features = []
        labels = []
        raw_ingest_keys = []
        for idx, row in enumerate(prepared_rows):
            label = 0 if row["label"] == "benign" else 1
            features.append([float(idx), float(label)])
            labels.append(label)
            raw_ingest_keys.append(row.get("raw_ingest_key"))
        dataset = {
            "reason": "wazuh_bootstrap_retrain",
            "features": features,
            "labels": labels,
            "feature_names": ["f1", "f2"],
            "feature_schema": "wazuh_native_v1",
            "label_map": {"0": "BENIGN", "1": "NMAP_BASIC_SCAN", "2": "OTHER_ATTACK"},
            "report": report or {},
            "_training_raw_ingest_keys": raw_ingest_keys,
        }
        dataset.update(self.db_dataset)
        return dataset

    def load_rows(self, raw_file_path: str):
        assert raw_file_path.endswith(".json")
        if self.file_error:
            raise RuntimeError(self.file_error)
        return self.file_dataset or [{"ingest_key": f"file-{idx}", "payload": {"label": "benign"}} for idx in range(60)]


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
            "retrain_historical_base_target": 25000,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(
        rows=[
            {"ingest_key": f"rk{idx}", "payload": {"label": ("nmap_basic_scan" if idx % 3 == 0 else "benign"), "timestamp": f"2026-05-{(idx % 28) + 1:02d}T00:00:00Z"}}
            for idx in range(60)
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
    assert len(dataset["features"]) == 62
    assert dataset["labels"].count(0) >= 2
    assert dataset["report"]["source"] == "mongodb"
    assert dataset["report"]["source_row_count"] == 60
    assert dataset["report"]["historical_base_samples"] == 0
    assert dataset["report"]["recent_slice_samples"] == 60
    assert dataset["report"]["final_pre_feedback_samples"] == 60
    assert dataset["report"]["final_total_samples"] == 62
    assert dataset["report"]["selection_strategy"] == "balanced_historical_base_plus_recent_slice"


def test_build_dataset_falls_back_to_file_when_db_rows_fail() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type(
        "S",
        (),
        {
            "raw_wazuh_training_path": "C:/tmp/raw.json",
            "min_samples_per_attack_class": 50,
            "retrain_raw_wazuh_db_limit": 123,
            "retrain_historical_base_target": 25000,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(rows=[{"payload": {"rule": {"description": "only one row"}}}])
    service._dataset_builder = _FakeBuilder(
        db_error="Only 1 usable raw Wazuh events found",
        file_dataset=[{"ingest_key": f"file-{idx}", "payload": {"label": ("nmap_basic_scan" if idx % 4 == 0 else "benign")}} for idx in range(60)],
    )

    async def fake_fetch_feedback_sets():
        return {"confirmed_known": [], "false_positive_log_ids": set()}

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]

    dataset = asyncio.run(MLModelOpsService._build_dataset(service))

    assert dataset["report"]["source"] == "file_fallback"
    assert dataset["report"]["source_path"] == "C:/tmp/raw.json"
    assert dataset["report"]["recent_slice_target"] == 123
    assert service._raw_wazuh_logs.last_limit == 50000


def test_build_dataset_raises_clear_error_when_db_and_file_unavailable() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._settings = type(
        "S",
        (),
        {
            "raw_wazuh_training_path": "C:/tmp/raw.json",
            "min_samples_per_attack_class": 50,
            "retrain_raw_wazuh_db_limit": 10000,
            "retrain_historical_base_target": 25000,
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
            "retrain_historical_base_target": 25000,
        },
    )()
    service._logs = _FakeLogsRepo()
    service._raw_wazuh_logs = _FakeRawRepo(rows=[{"payload": {"rule": {"description": "only one row"}}}])
    service._dataset_builder = _FakeBuilder(
        db_error="Only 1 usable raw Wazuh events found",
        file_dataset=[{"ingest_key": f"file-{idx}", "payload": {"label": ("nmap_basic_scan" if idx % 4 == 0 else "benign")}} for idx in range(60)],
    )

    async def fake_fetch_feedback_sets():
        return {"confirmed_known": [], "false_positive_log_ids": set()}

    service._fetch_feedback_sets = fake_fetch_feedback_sets  # type: ignore[method-assign]

    asyncio.run(MLModelOpsService._build_dataset(service))

    assert service._raw_wazuh_logs.last_limit == 50000


def test_compose_balanced_dataset_deduplicates_recent_and_historical_rows() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._dataset_builder = _FakeBuilder()

    rows = [
        {"ingest_key": f"hist-{idx}", "payload": {"label": "benign", "timestamp": f"2026-05-{(idx % 28) + 1:02d}T00:00:00Z"}}
        for idx in range(55)
    ]
    rows.extend(
        {"ingest_key": f"recent-{idx}", "payload": {"label": "nmap_basic_scan", "timestamp": f"2026-06-{(idx % 28) + 1:02d}T00:00:00Z"}}
        for idx in range(10)
    )
    rows.append({"ingest_key": "recent-0", "payload": {"label": "nmap_basic_scan", "timestamp": "2026-06-20T00:00:00Z"}})

    dataset = MLModelOpsService._compose_balanced_dataset_from_rows(service, rows, 50, 10, 25)

    assert dataset["report"]["historical_base_samples"] > 0
    assert dataset["report"]["recent_slice_samples"] == 10
    assert dataset["report"]["final_pre_feedback_samples"] == len(dataset["features"])
    assert len(dataset["features"]) == len(set(dataset["_training_raw_ingest_keys"]))


def test_recover_incomplete_jobs_marks_orphans_failed() -> None:
    service = MLModelOpsService.__new__(MLModelOpsService)
    service._jobs = _FakeJobsRepo(count=3)

    count = asyncio.run(MLModelOpsService.recover_incomplete_jobs(service))

    assert count == 3
    assert service._jobs.last_error == "Backend restarted before retrain completed"
