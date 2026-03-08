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
