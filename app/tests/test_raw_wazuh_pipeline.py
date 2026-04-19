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
