"""SMOTE oversampling (Chawla et al. 2002), implemented with scikit-learn only.

Applied ONLY to training folds, never to validation/test data, so measured metrics are not inflated
by synthetic samples leaking across the split.
"""
from __future__ import annotations

import numpy as np
from sklearn.neighbors import NearestNeighbors


def smote(X: np.ndarray, y: np.ndarray, ratio: float = 0.35, k: int = 5, seed: int = 0,
          round_columns=None):
    """Oversample every class up to `ratio * size_of_majority_class`.

    round_columns: indices of binary-flag columns, rounded back to {0,1} after interpolation.
    """
    rng = np.random.default_rng(seed)
    classes, counts = np.unique(y, return_counts=True)
    target = int(ratio * counts.max())
    X_out, y_out = [X], [y]
    for cls, cnt in zip(classes, counts):
        need = target - cnt
        if need <= 0:
            continue
        Xc = X[y == cls]
        if len(Xc) == 1:
            synth = np.repeat(Xc, need, axis=0)
        else:
            kk = min(k, len(Xc) - 1)
            nn = NearestNeighbors(n_neighbors=kk + 1).fit(Xc)
            neigh = nn.kneighbors(Xc, return_distance=False)[:, 1:]
            base = rng.integers(0, len(Xc), need)
            pick = neigh[base, rng.integers(0, kk, need)]
            gap = rng.random((need, 1))
            synth = Xc[base] + gap * (Xc[pick] - Xc[base])
        if round_columns is not None and len(round_columns):
            synth[:, round_columns] = np.round(synth[:, round_columns])
        X_out.append(synth)
        y_out.append(np.full(len(synth), cls, dtype=y.dtype))
    return np.vstack(X_out), np.concatenate(y_out)
