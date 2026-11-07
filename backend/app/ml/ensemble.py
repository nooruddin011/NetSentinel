"""Weighted soft-voting ensemble over heterogeneous classifiers."""
from __future__ import annotations

import numpy as np


class ThreatEnsemble:
    """Members must be fitted estimators exposing predict_proba with columns aligned to `classes`."""

    def __init__(self, members: dict, weights: dict, classes: list):
        self.members = members
        total = sum(weights.values()) or 1.0
        self.weights = {k: v / total for k, v in weights.items()}
        self.classes = list(classes)

    def member_proba(self, name: str, X: np.ndarray) -> np.ndarray:
        return self.members[name].predict_proba(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        out = np.zeros((X.shape[0], len(self.classes)))
        for name, est in self.members.items():
            out += self.weights[name] * est.predict_proba(X)
        return out
