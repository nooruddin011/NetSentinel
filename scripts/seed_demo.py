#!/usr/bin/env python3
"""Fill the database with ~24 h of back-dated simulated history so charts, heatmap and forecast are populated.

Safe to run repeatedly (it only adds data). Uses the same detection pipeline as live traffic."""
import argparse
import time

import _bootstrap  # noqa: F401
import numpy as np

from app.bootstrap import build_context
from app.config import get_settings
from app.services.detection.pipeline import normalize_event
from app.services.ingestion.simulator import TrafficSimulator


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", type=int, default=2500)
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    ctx = build_context(get_settings())
    rng = np.random.default_rng(a.seed)
    now = time.time()
    sim = TrafficSimulator(attack_ratio=0.15, seed=a.seed, stealth=0.1)
    events = []
    for _ in range(a.events):
        age = rng.uniform(0, a.hours * 3600)
        hour = (now - age) % 86400 / 3600
        burst = 0.12 + 0.22 * np.exp(-((hour - 3.0) ** 2) / 8)  # a quiet-hours attack window makes the heatmap interesting
        sim.attack_ratio = float(burst)
        raw = sim.next_event()
        raw["ts"] = now - age
        events.append(normalize_event(raw))
    events.sort(key=lambda e: e["ts"])
    dets = []
    for s in range(0, len(events), 1000):
        dets += ctx.pipeline.analyze_many(events[s:s + 1000])
    n_alerts, n_new = ctx.repo.record_bulk(list(zip(events, dets)), origin="seed", store_benign=True,
                                           dedupe_window=ctx.settings.dedupe_window_seconds)
    print(f"seeded {len(events)} events -> {n_new} new alerts ({n_alerts} threat events)")


if __name__ == "__main__":
    main()
