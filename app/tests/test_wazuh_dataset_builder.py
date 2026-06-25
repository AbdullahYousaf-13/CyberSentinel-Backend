import json

import pytest

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
    assert dataset["report"]["source_path"] == str(dataset_file)


def test_dataset_builder_builds_from_raw_rows() -> None:
    rows = [
        {
            "timestamp": "2026-05-01T10:00:00Z",
            "full_log": '127.0.0.1 - - [01/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
            "rule": {"level": 3, "description": "normal request"},
            "decoder": {"name": "web-accesslog"},
            "agent": {"name": "sensor"},
            "data": {"srcip": "1.1.1.1", "dstip": "2.2.2.2"},
        },
        {
            "timestamp": "2026-05-01T10:00:10Z",
            "full_log": 'nmap -sV --script vuln 10.0.0.4',
            "rule": {"level": 9, "description": "scanner detected"},
            "decoder": {"name": "json"},
            "agent": {"name": "sensor"},
            "data": {"srcip": "3.3.3.3", "dstip": "2.2.2.2"},
        },
    ] * 30

    builder = WazuhDatasetBuilder()
    dataset = builder.build_from_rows(rows, min_samples_per_class=1)

    assert dataset["feature_schema"] == "wazuh_native_v1"
    assert len(dataset["features"]) == len(dataset["labels"])
    assert dataset["report"]["samples"] == len(dataset["labels"])


def test_dataset_builder_builds_from_engineered_rows() -> None:
    rows = [
        {
            "metadata": {
                "raw_wazuh_payload": {
                    "timestamp": "2026-05-01T10:00:00Z",
                    "full_log": '127.0.0.1 - - [01/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
                    "rule": {"level": 3, "description": "normal request"},
                    "decoder": {"name": "web-accesslog"},
                    "agent": {"name": "sensor"},
                    "data": {"srcip": "1.1.1.1", "dstip": "2.2.2.2"},
                }
            }
        },
        {
            "metadata": {
                "raw_wazuh_payload": {
                    "timestamp": "2026-05-01T10:00:10Z",
                    "full_log": 'nmap -sV --script vuln 10.0.0.4',
                    "rule": {"level": 9, "description": "scanner detected"},
                    "decoder": {"name": "json"},
                    "agent": {"name": "sensor"},
                    "data": {"srcip": "3.3.3.3", "dstip": "2.2.2.2"},
                }
            }
        },
    ] * 30

    builder = WazuhDatasetBuilder()
    dataset = builder.build_from_rows(rows, min_samples_per_class=1)

    assert dataset["label_map"]["0"] == "BENIGN"
    assert dataset["report"]["samples"] == len(dataset["labels"])


def test_dataset_builder_requires_minimum_rows() -> None:
    builder = WazuhDatasetBuilder()

    with pytest.raises(RuntimeError, match="Only 1 raw Wazuh events available; expected at least 50"):
        builder.build_from_rows(
            [
                {
                    "payload": {
                        "timestamp": "2026-05-01T10:00:00Z",
                        "full_log": '127.0.0.1 - - [01/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
                        "rule": {"level": 3, "description": "normal request"},
                        "decoder": {"name": "web-accesslog"},
                        "agent": {"name": "sensor"},
                    }
                }
            ]
        )


def test_dataset_builder_requires_class_diversity() -> None:
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
        }
    ] * 60

    builder = WazuhDatasetBuilder()
    dataset = builder.build_from_rows(rows, min_samples_per_class=1)

    assert len(set(dataset["labels"])) == 1
