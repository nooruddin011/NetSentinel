"""A trained, self-contained detector: ensemble + anomaly model + tuned threshold + metadata."""
from __future__ import annotations

import numpy as np

from app.models.attacks import BENIGN


class ThreatModelBundle:
    def __init__(self, ensemble, anomaly, classes, tau, baseline, report=None, version="1", unknown_conf=0.7):
        self.ensemble = ensemble
        self.anomaly = anomaly
        self.classes = list(classes)
        self.benign_idx = self.classes.index(BENIGN)
        self.tau = float(tau)
        self.baseline = np.asarray(baseline, dtype=float)
        self.report = report or {}
        self.version = version
        # An anomalous event whose best known-attack probability is below this is labelled Zero-Day.
        # Higher = more zero-days labelled, but more hard known attacks relabelled (see docs/ML_PIPELINE.md).
        self.unknown_conf = unknown_conf

    @property
    def member_names(self):
        return list(self.ensemble.members)

    def classify(self, X: np.ndarray, unknown_conf: float | None = None) -> dict:
        """Hybrid ML decision: tuned-threshold ensemble + autoencoder zero-day logic."""
        unknown_conf = getattr(self, "unknown_conf", 0.7) if unknown_conf is None else unknown_conf
        X = np.asarray(X, dtype=np.float64)
        proba = self.ensemble.predict_proba(X)
        b = self.benign_idx
        attack_score = 1.0 - proba[:, b]
        atk = proba.copy()
        atk[:, b] = -1.0
        top = atk.argmax(axis=1)
        rows = np.arange(len(X))
        is_attack = attack_score >= self.tau
        label_idx = np.where(is_attack, top, b)
        conf = np.where(is_attack, proba[rows, top], proba[:, b])
        ratio = self.anomaly.score(X)
        anomalous = ratio >= 1.0
        unknown = anomalous & (~is_attack | (proba[rows, top] < unknown_conf))
        labels = [self.classes[i] for i in label_idx]
        for i in np.flatnonzero(unknown):
            labels[i] = "Zero-Day"
            conf[i] = 1.0 - 1.0 / (1.0 + ratio[i])
        return dict(labels=labels, confidence=conf, attack_score=attack_score, anomaly_ratio=ratio,
                    proba=proba, label_idx=label_idx, unknown=unknown)
