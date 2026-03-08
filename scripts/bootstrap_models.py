import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import existing sklearn model artifacts into CyberSentinel registry format."
    )
    parser.add_argument(
        "--iforest",
        required=True,
        help="Path to isolation forest model file (.pkl or .joblib)",
    )
    parser.add_argument(
        "--rf",
        required=True,
        help="Path to random forest model file (.pkl or .joblib)",
    )
    parser.add_argument(
        "--model-dir",
        default="app/ml/models",
        help="Target model directory used by backend (default: app/ml/models)",
    )
    parser.add_argument(
        "--reason",
        default="Imported from local training artifacts",
        help="Reason recorded in metadata",
    )
    parser.add_argument(
        "--expected-features",
        type=int,
        default=78,
        help="Expected feature count used by backend extractor (default: 78)",
    )
    parser.add_argument(
        "--allow-feature-mismatch",
        action="store_true",
        help="Allow import even if model feature count does not match expected-features",
    )
    return parser.parse_args()


def feature_count(model: Any, label: str) -> int:
    if not hasattr(model, "n_features_in_"):
        raise ValueError(f"{label} model is missing n_features_in_")
    return int(model.n_features_in_)


def main() -> None:
    args = parse_args()
    iforest_path = Path(args.iforest)
    rf_path = Path(args.rf)
    if not iforest_path.exists():
        raise FileNotFoundError(f"Isolation Forest file not found: {iforest_path}")
    if not rf_path.exists():
        raise FileNotFoundError(f"Random Forest file not found: {rf_path}")

    iforest = joblib.load(iforest_path)
    rf = joblib.load(rf_path)

    iforest_features = feature_count(iforest, "Isolation Forest")
    rf_features = feature_count(rf, "Random Forest")
    if iforest_features != rf_features:
        raise ValueError(
            "Model-to-model feature mismatch: isolation_forest expects "
            f"{iforest_features}, random_forest expects {rf_features}"
        )

    if iforest_features != args.expected_features and not args.allow_feature_mismatch:
        raise ValueError(
            "Model feature count does not match backend extractor expectation. "
            f"expected={args.expected_features}, model={iforest_features}. "
            "Use --allow-feature-mismatch only if you also changed backend feature extraction."
        )

    model_dir = Path(args.model_dir)
    versions_dir = model_dir / "versions"
    versions_dir.mkdir(parents=True, exist_ok=True)

    version = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    version_dir = versions_dir / version
    version_dir.mkdir(parents=True, exist_ok=True)

    out_iforest = version_dir / "isolation_forest.joblib"
    out_rf = version_dir / "random_forest.joblib"
    joblib.dump(iforest, out_iforest)
    joblib.dump(rf, out_rf)

    metadata = {
        "version": version,
        "trained_at": datetime.utcnow().isoformat(),
        "reason": args.reason,
        "hashes": {
            "isolation_forest": sha256(out_iforest),
            "random_forest": sha256(out_rf),
        },
        "feature_count": iforest_features,
        "source": {
            "isolation_forest": str(iforest_path.resolve()),
            "random_forest": str(rf_path.resolve()),
        },
    }
    (version_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="ascii")
    (model_dir / "registry.json").write_text(
        json.dumps({"active_version": version}, indent=2), encoding="ascii"
    )

    print(f"Imported model version: {version}")
    print(f"Feature count: {iforest_features}")
    print(f"Registry path: {(model_dir / 'registry.json').resolve()}")
    print(f"Version path: {version_dir.resolve()}")


if __name__ == "__main__":
    main()
