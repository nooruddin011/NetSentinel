#!/usr/bin/env python3
"""Train the detection models and save the active bundle.

Examples
  python scripts/train_models.py                       # full run on simulated data (a few minutes)
  python scripts/train_models.py --quick               # fast smoke run (~1 min)
  python scripts/train_models.py --csv my_labelled.csv # your own labelled CSV (platform schema; `label` column)
  python scripts/train_models.py --nslkdd KDDTrain+.txt  # NSL-KDD (coarse mapping, see docs/datasets)
"""
import argparse
import json
import logging
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import get_settings  # noqa: E402
from app.ml.registry import save_bundle  # noqa: E402
from app.ml.trainer import TrainConfig, train  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="smaller/faster configuration")
    ap.add_argument("--samples", type=int, help="synthetic rows")
    ap.add_argument("--folds", type=int, help="stratified CV folds")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--csv", help="labelled CSV in the platform schema")
    ap.add_argument("--nslkdd", help="path to an NSL-KDD file (e.g. KDDTrain+.txt)")
    ap.add_argument("--out", help="output directory (default: MODEL_DIR from config)")
    ap.add_argument("--target-fpr", type=float, default=0.01, help="benign false-positive rate the threshold is tuned to")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    kw = dict(seed=a.seed, target_fpr=a.target_fpr)
    if a.samples:
        kw["n_samples"] = a.samples
    if a.folds:
        kw["cv_folds"] = a.folds
    cfg = TrainConfig.quick(**kw) if a.quick else TrainConfig(**kw)
    tmp = None
    if a.nslkdd:
        from app.services.ingestion.loader import load_nslkdd
        df = load_nslkdd(a.nslkdd)
        print(f"NSL-KDD adapter: {len(df)} rows kept, {df.attrs.get('dropped', 0)} unmapped attack rows dropped")
        tmp = Path(tempfile.mkdtemp()) / "nslkdd_mapped.csv"
        df.to_csv(tmp, index=False)
        a.csv = str(tmp)
    if a.csv:
        cfg.dataset, cfg.csv_path = "csv", a.csv

    bundle = train(cfg, progress=lambda s, f: print(f"[{f:4.0%}] {s}"))
    out = Path(a.out) if a.out else get_settings().model_dir
    save_bundle(bundle, out)
    r = bundle.report
    print(f"\nSaved to {out}  (training took {r['training_seconds']}s)")
    print(f"{'model':20s} {'acc':>6s} {'prec':>6s} {'rec':>6s} {'f1':>6s} {'auc':>6s} {'FPR':>6s} {'ms':>6s}")
    for n, m in r["models"].items():
        print(f"{n:20s} {m['accuracy']:6.3f} {m['precision']:6.3f} {m['recall']:6.3f} {m['f1']:6.3f} {m['roc_auc']:6.3f} "
              f"{m['false_positive_rate']:6.3f} {m['infer_ms']:6.1f}")
    print("hybrid:", json.dumps(r["hybrid"]))
    if r["dataset"]["synthetic"]:
        print("NOTE: metrics are from SIMULATED data - they show the pipeline works, not real-world accuracy.")


if __name__ == "__main__":
    main()
