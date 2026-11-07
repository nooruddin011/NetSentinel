"""Autoencoder anomaly detector (scikit-learn MLP trained to reconstruct benign traffic).

Rationale: supervised classifiers can only recognise attacks they were trained on. An autoencoder
trained on benign traffic only has a high reconstruction error on traffic unlike anything it has
seen, which is how unknown / zero-day behaviour is surfaced.
"""
from __future__ import annotations

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler


class AutoencoderDetector:
    def __init__(self, hidden=(24, 10, 24), max_iter=250, seed=42):
        self.hidden, self.max_iter, self.seed = hidden, max_iter, seed
        self.scaler = StandardScaler()
        self.net = None
        self.threshold = 1.0

    def _prep(self, X):
        return np.clip(self.scaler.transform(X), -8, 8)

    def fit(self, X_benign: np.ndarray):
        Xs = np.clip(self.scaler.fit_transform(X_benign), -8, 8)
        self.net = MLPRegressor(hidden_layer_sizes=self.hidden, activation="relu", max_iter=self.max_iter,
                                early_stopping=True, n_iter_no_change=12, random_state=self.seed)
        self.net.fit(Xs, Xs)
        return self

    def errors(self, X: np.ndarray) -> np.ndarray:
        Xs = self._prep(X)
        return np.mean((self.net.predict(Xs) - Xs) ** 2, axis=1)

    def feature_errors(self, X: np.ndarray) -> np.ndarray:
        Xs = self._prep(X)
        return (self.net.predict(Xs) - Xs) ** 2

    def calibrate(self, X_benign_val: np.ndarray, percentile: float = 99.5):
        self.threshold = float(np.percentile(self.errors(X_benign_val), percentile))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Reconstruction error divided by the calibrated threshold; >= 1 means anomalous."""
        return self.errors(X) / max(self.threshold, 1e-9)
