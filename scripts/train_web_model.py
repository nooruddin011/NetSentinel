#!/usr/bin/env python3
"""Train (or retrain) the web-request text model and save it to models/web/.

  python scripts/train_web_model.py                       # generated corpus (about 15 s)
  python scripts/train_web_model.py --csv requests.csv    # your labelled requests (columns: path,query,label)
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import get_settings  # noqa: E402
from app.ml.webregistry import save_web_model  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", help="labelled requests: path,query,label (Benign / SQL Injection / XSS / Path Traversal / Command Injection)")
    ap.add_argument("--out", help="output directory (default: WEB_MODEL_DIR)")
    ap.add_argument("--per-attack", type=int, default=1500)
    ap.add_argument("--benign", type=int, default=9000)
    a = ap.parse_args()
    if a.csv:
        import pandas as pd
        from app.ml import webmodel
        from app.ml.webcorpus import CLASSES
        df = pd.read_csv(a.csv).fillna("")
        bad = sorted(set(df["label"]) - set(CLASSES))
        if bad:
            sys.exit(f"unknown labels: {bad}; use {CLASSES}")
        rows = [(str(r.path), str(r.query), r.label, "csv") for r in df.itertuples()]
        model = webmodel._fit(rows, 7)
        report = dict(synthetic=False, corpus=dict(rows=len(rows), source=str(a.csv)), leak_audit=webmodel.structure_leak_audit(rows),
                      note="Trained on user-supplied data. No held-out-family evaluation was run: hold out a time period yourself and report it.")
    else:
        from app.ml.webmodel import train_web_model
        model, report = train_web_model(a.per_attack, a.benign, progress=lambda s, f: print(f"[{f:4.0%}] {s}"))
        h = report["held_out_families"]["combined"]
        print(f"held-out families: detection {h['detection_rate']:.3f}, false positives {h['false_positive_rate']:.4f}; leak audit {report['leak_audit']['structure_only_auc']}")
    out = Path(a.out) if a.out else get_settings().web_model_dir
    save_web_model(model, report, out)
    print("saved to", out)


if __name__ == "__main__":
    main()
