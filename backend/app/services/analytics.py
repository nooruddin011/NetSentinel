"""Attack-trend forecasting (Holt linear exponential smoothing) -- simple, explainable, dependency-free."""
from __future__ import annotations

import numpy as np


def holt_forecast(series, horizon: int = 6, alpha: float = 0.5, beta: float = 0.2) -> dict:
    y = np.asarray(series, dtype=float)
    if len(y) < 4 or not np.isfinite(y).all():
        return dict(forecast=[0.0] * horizon, lower=[0.0] * horizon, upper=[0.0] * horizon, method="insufficient-data")
    level, trend = y[0], y[1] - y[0]
    resid = []
    for v in y[1:]:
        pred = level + trend
        resid.append(v - pred)
        new_level = alpha * v + (1 - alpha) * (level + trend)
        trend = beta * (new_level - level) + (1 - beta) * trend
        level = new_level
    sd = float(np.std(resid)) if resid else 0.0
    fc = [max(0.0, level + (h + 1) * trend) for h in range(horizon)]
    band = [1.28 * sd * np.sqrt(h + 1) for h in range(horizon)]  # ~80% interval
    return dict(forecast=[round(v, 2) for v in fc], lower=[round(max(0.0, f - b), 2) for f, b in zip(fc, band)],
                upper=[round(f + b, 2) for f, b in zip(fc, band)], method="holt-linear")
