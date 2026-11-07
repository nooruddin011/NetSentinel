"""Save/load the web text model with the same checksum protection as the flow models."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib

from app.ml.registry import _sha256
from app.ml.webmodel import WebTextModel, train_web_model

log = logging.getLogger(__name__)
FILE = "web_model.joblib"


def save_web_model(model, report, model_dir) -> Path:
    d = Path(model_dir); d.mkdir(parents=True, exist_ok=True)
    path = d / FILE
    tmp = path.with_suffix(".tmp")
    joblib.dump(dict(model=model, report=report), tmp, compress=3)
    tmp.replace(path)
    (d / (FILE + ".sha256")).write_text(_sha256(path) + "\n", encoding="utf-8")
    (d / "metrics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def load_web_model(model_dir):
    d = Path(model_dir)
    path, sha = d / FILE, d / (FILE + ".sha256")
    if not path.is_file() or not sha.is_file():
        raise FileNotFoundError(f"no web model in {d}")
    if _sha256(path) != sha.read_text(encoding="utf-8").strip():
        raise ValueError("web model checksum mismatch - refusing to load")
    obj = joblib.load(path)
    if not isinstance(obj, dict) or not isinstance(obj.get("model"), WebTextModel):
        raise ValueError("unexpected object in web model bundle")
    return obj["model"], obj.get("report", {})


def load_or_train_web(model_dir):
    try:
        return load_web_model(model_dir)
    except Exception as exc:
        log.warning("Could not load the web model (%s). Training a new one (about 10 seconds)...", exc)
    model, report = train_web_model()
    save_web_model(model, report, model_dir)
    return model, report
