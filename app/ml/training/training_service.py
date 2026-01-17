from typing import Tuple

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier


def train_isolation_forest(features: np.ndarray) -> IsolationForest:
    model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
    model.fit(features)
    return model


def train_random_forest(features: np.ndarray, labels: np.ndarray) -> RandomForestClassifier:
    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model.fit(features, labels)
    return model


def train_models(features: np.ndarray, labels: np.ndarray) -> Tuple[IsolationForest, RandomForestClassifier]:
    iforest = train_isolation_forest(features)
    rf = train_random_forest(features, labels)
    return iforest, rf
