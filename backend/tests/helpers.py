"""Shared test fixtures: one tiny trained bundle (built once per process) and a ready-made context."""
from __future__ import annotations

import os
import tempfile
import warnings

warnings.filterwarnings("ignore")
_BUNDLE = None


def get_bundle():
    global _BUNDLE
    if _BUNDLE is None:
        from app.ml.trainer import TrainConfig, train
        _BUNDLE = train(TrainConfig(n_samples=4000, cv_folds=2, rf_trees=40, gb_iter=30, mlp_hidden=(32, 16), mlp_iter=40,
                                    novel_n=300, use_xgboost=False, use_lightgbm=False))
    return _BUNDLE


def make_settings(tmp: str, **over):
    from app.config import Settings
    s = Settings(db_path=__import__("pathlib").Path(tmp) / "t.db", model_dir=__import__("pathlib").Path(tmp) / "models",
                 jwt_secret="test-secret-test-secret-test-secret", admin_password="Admin-Passw0rd!", simulation_enabled=False)
    for k, v in over.items():
        setattr(s, k, v)
    return s


def make_ctx(tmp: str | None = None, **over):
    from app.bootstrap import build_context
    tmp = tmp or tempfile.mkdtemp()
    return build_context(make_settings(tmp, **over), bundle=get_bundle(), web_model=get_web_model())


_WEB = None


def get_web_model():
    """Small, quickly trained web text model for tests (the shipped one is used in the independent-probe test)."""
    global _WEB
    if _WEB is None:
        from app.ml.webmodel import train_web_model
        _WEB = train_web_model(n_per_attack=400, n_benign=2400, evaluate=False)[0]
    return _WEB
