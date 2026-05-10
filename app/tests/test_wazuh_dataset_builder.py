import json

from app.ml.training.wazuh_dataset_builder import WazuhDatasetBuilder


def test_dataset_builder_builds_wazuh_bootstrap_dataset(tmp_path) -> None:
    rows = [
        {
            "payload": {
                "timestamp": "2026-05-01T10:00:00Z",
                "full_log": '127.0.0.1 - - [01/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
                "rule": {"level": 3, "description": "normal request"},
                "decoder": {"name": "web-accesslog"},
                "agent": {"name": "sensor"},
                "data": {"srcip": "1.1.1.1", "dstip": "2.2.2.2"},
            }
        },
        {
            "payload": {
                "timestamp": "2026-05-01T10:00:10Z",
                "full_log": 'nmap -sV --script vuln 10.0.0.4',
                "rule": {"level": 9, "description": "scanner detected"},
                "decoder": {"name": "json"},
                "agent": {"name": "sensor"},
                "data": {"srcip": "3.3.3.3", "dstip": "2.2.2.2"},
            }
        },
    ]
    # Pad to exceed minimum rows check.
    rows = rows * 30
    dataset_file = tmp_path / "raw.json"
    dataset_file.write_text(json.dumps(rows), encoding="utf-8")

    builder = WazuhDatasetBuilder()
    dataset = builder.build(str(dataset_file), min_samples_per_class=1)

    assert dataset["feature_schema"] == "wazuh_native_v1"
    assert len(dataset["features"]) == len(dataset["labels"])
    assert dataset["label_map"]["0"] == "BENIGN"
    assert dataset["report"]["samples"] == len(dataset["labels"])
