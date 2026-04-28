from app.ml.features.feature_extractor import FeatureExtractor


def test_feature_extractor_outputs_78_features() -> None:
    extractor = FeatureExtractor()
    logs = [
        {
            "source": "sensor-a",
            "message": "test",
            "metadata": {
                "Destination Port": 443,
                "Flow Duration": "1000",
                "Total Fwd Packets": 10,
            },
        },
        {
            "source": "sensor-b",
            "message": "test",
            "metadata": {
                "destination_port": 80,
                "flow_duration": 500,
                "total_fwd_packets": "2",
            },
        },
    ]

    features = extractor.transform(logs)

    assert features.shape == (2, 78)
    assert features[0, 0] == 443.0
    assert features[0, 1] == 1000.0
    assert features[0, 2] == 10.0
    assert features[1, 0] == 80.0
    assert features[1, 1] == 500.0
    assert features[1, 2] == 2.0


def test_feature_extractor_maps_nested_wazuh_keys() -> None:
    extractor = FeatureExtractor()
    logs = [
        {
            "source": "kali",
            "message": "test",
            "metadata": {
                "data_dstport": 8080,
                "data_flow_duration": "2500",
                "data_total_fwd_packets": "3",
            },
        }
    ]

    features = extractor.transform(logs)

    assert features.shape == (1, 78)
    assert features[0, 0] == 8080.0
    assert features[0, 1] == 2500.0
    assert features[0, 2] == 3.0


def test_feature_extractor_derives_http_proxy_features_from_nginx_log() -> None:
    extractor = FeatureExtractor()
    logs = [
        {
            "source": "kali",
            "message": '127.0.0.1 - - [28/Apr/2026:18:30:52 +0500] "GET /wp-config.php.bak HTTP/1.1" 200 75055 "-" "Mozilla/5.0"',
            "metadata": {"raw_wazuh_payload": {"full_log": '127.0.0.1 - - [28/Apr/2026:18:30:52 +0500] "GET /wp-config.php.bak HTTP/1.1" 200 75055 "-" "Mozilla/5.0"'}},
        }
    ]

    features = extractor.transform(logs)

    # Destination Port
    assert features[0, 0] == 0.0
    # Total Fwd Packets
    assert features[0, 2] == 1.0
    # Total Length of Bwd Packets
    assert features[0, 5] == 75055.0
