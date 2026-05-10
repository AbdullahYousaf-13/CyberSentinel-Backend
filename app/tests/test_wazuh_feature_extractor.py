from app.ml.features.wazuh_feature_extractor import WazuhFeatureExtractor


def test_wazuh_feature_extractor_outputs_expected_shape() -> None:
    extractor = WazuhFeatureExtractor()
    logs = [
        {
            "timestamp": "2026-05-01T10:00:00Z",
            "source": "wazuh",
            "message": '127.0.0.1 - - [01/May/2026:10:00:00 +0000] "GET /wp-config.php.bak HTTP/1.1" 404 120 "-" "Mozilla/5.0"',
            "metadata": {
                "raw_wazuh_payload": {
                    "rule": {"level": 12, "firedtimes": 4, "id": "31151"},
                    "decoder": {"name": "web-accesslog"},
                    "agent": {"name": "sensor-1"},
                    "data": {"srcip": "1.1.1.1", "dstip": "2.2.2.2"},
                }
            },
        }
    ]
    features = extractor.transform(logs)
    assert features.shape == (1, len(extractor.FEATURE_NAMES))
    assert features[0, extractor.FEATURE_NAMES.index("rule_level")] == 12.0
