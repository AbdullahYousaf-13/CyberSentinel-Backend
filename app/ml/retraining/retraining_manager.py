import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import sklearn


class RetrainingManager:
    def __init__(self, model_dir: str) -> None:
        self._model_dir = Path(model_dir)
        self._registry_path = self._model_dir / "registry.json"
        self._versions_path = self._model_dir / "versions"
        self._versions_path.mkdir(parents=True, exist_ok=True)

    def get_active_version(self) -> str:
        if not self._registry_path.exists():
            raise FileNotFoundError("Model registry not initialized")
        data = json.loads(self._registry_path.read_text(encoding="ascii"))
        return data["active_version"]

    def set_active_version(self, version: str) -> None:
        payload = {"active_version": version}
        self._registry_path.write_text(json.dumps(payload, indent=2), encoding="ascii")

    def save_new_version(self, iforest: Any, rf: Any, reason: str) -> str:
        version = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        version_path = self._versions_path / version
        version_path.mkdir(parents=True, exist_ok=True)
        iforest_path = version_path / "isolation_forest.joblib"
        rf_path = version_path / "random_forest.joblib"

        joblib.dump(iforest, iforest_path)
        joblib.dump(rf, rf_path)

        metadata = {
            "version": version,
            "trained_at": datetime.utcnow().isoformat(),
            "reason": reason,
            "hashes": {
                "isolation_forest": self._sha256(iforest_path),
                "random_forest": self._sha256(rf_path),
            },
            "library_versions": {
                "scikit_learn": sklearn.__version__,
                "joblib": joblib.__version__,
                "numpy": np.__version__,
            },
        }
        (version_path / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="ascii")
        self.set_active_version(version)
        return version

    def rollback(self, target_version: str) -> None:
        version_path = self._versions_path / target_version
        if not version_path.exists():
            raise FileNotFoundError("Target version not found")
        self.set_active_version(target_version)

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()
