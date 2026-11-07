#!/usr/bin/env python3
"""Generate a labelled sample CSV for the Upload page (simulated traffic, attacker IPs from RFC 5737 ranges)."""
import argparse
import time

import _bootstrap  # noqa: F401
import numpy as np
import pandas as pd

from app.ml.schema import RAW_FEATURES
from app.ml.synthetic import generate_event
from app.models.attacks import BENIGN
from app.services.ingestion.simulator import ATTACK_WEIGHTS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=400)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(_bootstrap.ROOT / "data" / "sample" / "sample_traffic.csv"))
    a = ap.parse_args()
    rng = np.random.default_rng(a.seed)
    names = [n for n in ATTACK_WEIGHTS if n != "Zero-Day"]
    w = np.array([ATTACK_WEIGHTS[n] for n in names], float)
    now = time.time()
    rows = []
    for i in range(a.rows):
        label = str(rng.choice(names, p=w / w.sum())) if rng.random() < 0.35 else BENIGN
        ev = generate_event(label, rng, stealth=0.1)
        row = {"ts": round(now - (a.rows - i) * 4.0, 2), "src_ip": ev["src_ip"], "dst_ip": ev["dst_ip"], "protocol": ev["protocol"]}
        row.update({k: ev[k] for k in RAW_FEATURES if k not in ("is_tcp", "is_udp", "is_icmp")})
        row["payload_sample"] = ev["payload_sample"]
        row["label"] = label
        rows.append(row)
    pd.DataFrame(rows).to_csv(a.out, index=False)
    print(f"wrote {a.rows} rows to {a.out}")


if __name__ == "__main__":
    main()
