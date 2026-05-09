from app.services.raw_wazuh_pipeline_service import RawWazuhPipelineService


def test_prepare_logs_dedupes_same_offset_key() -> None:
    logs = [
        {
            "payload": {"id": "abc", "timestamp": "2026-01-01T00:00:00Z"},
            "ingestMeta": {
                "archivePath": "/var/ossec/logs/archives/archives.json",
                "byteOffset": 100,
                "lineHash": "a" * 64,
            },
        },
        {
            "payload": {"id": "abc", "timestamp": "2026-01-01T00:00:00Z"},
            "ingestMeta": {
                "archivePath": "/var/ossec/logs/archives/archives.json",
                "byteOffset": 100,
                "lineHash": "a" * 64,
            },
        },
    ]

    prepared = RawWazuhPipelineService.prepare_logs_for_ingest(logs)
    assert len(prepared) == 1
    assert prepared[0]["ingest_meta"]["mode"] == "offset"


def test_prepare_logs_treats_different_offsets_as_distinct() -> None:
    logs = [
        {
            "payload": {"message": "same"},
            "ingestMeta": {
                "archivePath": "/var/ossec/logs/archives/archives.json",
                "byteOffset": 10,
                "lineHash": "b" * 64,
            },
        },
        {
            "payload": {"message": "same"},
            "ingestMeta": {
                "archivePath": "/var/ossec/logs/archives/archives.json",
                "byteOffset": 11,
                "lineHash": "b" * 64,
            },
        },
    ]

    prepared = RawWazuhPipelineService.prepare_logs_for_ingest(logs)
    assert len(prepared) == 2
    assert prepared[0]["ingest_key"] != prepared[1]["ingest_key"]


def test_engineer_log_prefers_full_log_for_message() -> None:
    service = RawWazuhPipelineService.__new__(RawWazuhPipelineService)
    from app.ml.features.wazuh_feature_engineer import WazuhFamilyFeatureEngineer

    service._extractor = WazuhFamilyFeatureEngineer()
    payload = {
        "timestamp": "2026-05-08T19:15:04.743+0500",
        "agent": {"name": "kali"},
        "decoder": {"name": "web-accesslog"},
        "rule": {"level": 10, "description": "GET request received."},
        "full_log": '127.0.0.1 - - [08/May/2026:22:39:11 +0500] "GET /.git/HEAD HTTP/1.1" 200 75055 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"',
    }

    engineered = service._engineer_log(payload, "ingest-1")

    assert engineered["message"].startswith("127.0.0.1 - - [08/May/2026:22:39:11 +0500]")
