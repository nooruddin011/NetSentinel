"""Model persistence with integrity verification.

joblib/pickle executes code on load, so a bundle is only loaded when its SHA-256 matches the
sidecar file written at save time. This blocks accidental corruption and casual tampering; it is not
a substitute for restricting write access to the model directory.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

import joblib

from app.ml.bundle import ThreatModelBundle
from app.ml.trainer import TrainConfig, train

log = logging.getLogger(__name__)
BUNDLE_FILE = "bundle.joblib"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def save_bundle(bundle: ThreatModelBundle, model_dir: Path) -> Path:
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    path = model_dir / BUNDLE_FILE
    tmp = path.with_suffix(".tmp")
    joblib.dump(bundle, tmp, compress=3)
    tmp.replace(path)
    (model_dir / (BUNDLE_FILE + ".sha256")).write_text(_sha256(path) + "\n", encoding="utf-8")
    (model_dir / "metrics.json").write_text(json.dumps(bundle.report, indent=2), encoding="utf-8")
    return path


def load_bundle(model_dir: Path) -> ThreatModelBundle:
    model_dir = Path(model_dir)
    path = model_dir / BUNDLE_FILE
    sha_file = model_dir / (BUNDLE_FILE + ".sha256")
    if not path.is_file() or not sha_file.is_file():
        raise FileNotFoundError(f"no model bundle in {model_dir}")
    if _sha256(path) != sha_file.read_text(encoding="utf-8").strip():
        raise ValueError("model bundle checksum mismatch - refusing to load")
    bundle = joblib.load(path)
    if not isinstance(bundle, ThreatModelBundle):
        raise ValueError("unexpected object in model bundle")
    return bundle


def load_or_train(model_dir: Path, quick: bool = True) -> ThreatModelBundle:
    """Load the active bundle; if it is missing/corrupt/incompatible, train a fresh one."""
    try:
        bundle = load_bundle(model_dir)
        log.info("Loaded model bundle (%s)", ", ".join(bundle.member_names))
        return bundle
    except Exception as exc:  # missing file, bad checksum, sklearn version mismatch, ...
        log.warning("Could not load model bundle (%s). Training a new one - this takes a minute or two.", exc)
    bundle = train(TrainConfig.quick() if quick else TrainConfig())
    save_bundle(bundle, model_dir)
    return bundle
