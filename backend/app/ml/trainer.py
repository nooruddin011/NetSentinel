"""Training + evaluation pipeline.

Steps: data -> stratified hold-out split -> stratified k-fold CV on the training part (SMOTE applied
inside each fold only) -> CV-weighted soft-voting ensemble -> threshold tuned on out-of-fold
predictions to cap the benign false-positive rate -> autoencoder trained on benign traffic only ->
evaluation on the untouched hold-out set and on a held-out *novel* (zero-day) family.
"""
from __future__ import annotations

import logging
import platform
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import warnings

import numpy as np
import pandas as pd
import sklearn
from sklearn.exceptions import ConvergenceWarning
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.ml.anomaly import AutoencoderDetector
from app.ml.bundle import ThreatModelBundle
from app.ml.ensemble import ThreatEnsemble
from app.ml.schema import FEATURES, FLAGS, engineer
from app.ml.smote import smote
from app.ml.synthetic import generate_dataset, sample_class
from app.models.attacks import BENIGN, CLASSES

log = logging.getLogger(__name__)
warnings.filterwarnings("ignore", category=ConvergenceWarning)

MODEL_INFO = {
    "random_forest": dict(display="Random Forest", approach="Signature-style supervised (bagged trees)",
                          complexity="Train O(T·n·log n·√d) · Infer O(T·depth)"),
    "gradient_boosting": dict(display="Gradient Boosting (HistGB)", approach="Supervised boosted trees",
                              complexity="Train O(T·n·d) histogram-based · Infer O(T·depth)"),
    "xgboost": dict(display="XGBoost", approach="Hybrid detection (regularised boosted trees)",
                    complexity="Train O(T·n·d) histogram-based · Infer O(T·depth)"),
    "lightgbm": dict(display="LightGBM", approach="Supervised leaf-wise boosted trees",
                     complexity="Train O(T·n·d) GOSS/histogram · Infer O(T·depth)"),
    "neural_network": dict(display="Neural Network (MLP)", approach="Behavioral analysis (learned non-linear features)",
                           complexity="Train O(epochs·n·Σ wᵢwᵢ₊₁) · Infer O(Σ wᵢwᵢ₊₁)"),
    "ensemble": dict(display="Weighted Ensemble", approach="Hybrid (CV-weighted soft voting)",
                     complexity="Sum of member costs"),
    "autoencoder": dict(display="Autoencoder", approach="Anomaly detection (unsupervised, zero-day)",
                        complexity="Train O(epochs·n·Σ wᵢwᵢ₊₁) · Infer O(Σ wᵢwᵢ₊₁)"),
}


@dataclass
class TrainConfig:
    dataset: str = "synthetic"
    csv_path: str | None = None
    n_samples: int = 15000
    seed: int = 42
    test_size: float = 0.2
    cv_folds: int = 5
    smote_ratio: float = 0.35
    target_fpr: float = 0.01
    rf_trees: int = 200
    gb_iter: int = 120
    mlp_hidden: tuple = (128, 64)
    mlp_iter: int = 120
    novel_n: int = 1500
    stealth: float = 0.2
    use_xgboost: bool = True
    use_lightgbm: bool = True
    extra: dict = field(default_factory=dict)

    @classmethod
    def quick(cls, **kw):
        base = dict(n_samples=8000, cv_folds=3, rf_trees=100, gb_iter=60, mlp_hidden=(64, 32), mlp_iter=60, novel_n=600)
        base.update(kw)
        return cls(**base)


def build_candidates(cfg: TrainConfig) -> dict:
    c = {
        "random_forest": lambda: RandomForestClassifier(n_estimators=cfg.rf_trees, class_weight="balanced_subsample",
                                                        n_jobs=-1, random_state=cfg.seed),
        "gradient_boosting": lambda: HistGradientBoostingClassifier(max_iter=cfg.gb_iter, learning_rate=0.1,
                                                                    max_leaf_nodes=31, early_stopping=False,
                                                                    random_state=cfg.seed),
        "neural_network": lambda: make_pipeline(
            StandardScaler(),
            MLPClassifier(hidden_layer_sizes=cfg.mlp_hidden, max_iter=cfg.mlp_iter, early_stopping=True,
                          n_iter_no_change=10, random_state=cfg.seed)),
    }
    if cfg.use_xgboost:
        try:
            from xgboost import XGBClassifier  # optional dependency
            c["xgboost"] = lambda: XGBClassifier(n_estimators=cfg.gb_iter, max_depth=6, learning_rate=0.1, subsample=0.9,
                                                 colsample_bytree=0.9, tree_method="hist", n_jobs=-1,
                                                 random_state=cfg.seed, eval_metric="mlogloss", verbosity=0)
        except Exception as exc:  # ImportError, or missing native libs
            log.info("XGBoost unavailable (%s); skipping", exc)
    if cfg.use_lightgbm:
        try:
            from lightgbm import LGBMClassifier  # optional dependency
            c["lightgbm"] = lambda: LGBMClassifier(n_estimators=cfg.gb_iter, learning_rate=0.1, num_leaves=31,
                                                   subsample=0.9, colsample_bytree=0.9, random_state=cfg.seed,
                                                   n_jobs=-1, verbose=-1)
        except Exception as exc:
            log.info("LightGBM unavailable (%s); skipping", exc)
    return c


# ------------------------------------------------------------------ decision rule & metrics
def decide(proba: np.ndarray, tau: float, b: int):
    score = 1.0 - proba[:, b]
    atk = proba.copy()
    atk[:, b] = -1.0
    pred = np.where(score >= tau, atk.argmax(axis=1), b)
    return pred, score


def choose_tau(proba_oof: np.ndarray, y: np.ndarray, b: int, target_fpr: float) -> float:
    ben_scores = (1.0 - proba_oof[:, b])[y == b]
    tau = float(np.quantile(ben_scores, 1.0 - target_fpr)) if len(ben_scores) else 0.5
    return float(np.clip(tau, 0.05, 0.9))


def _roc_points(y_bin, score):
    fpr, tpr, _ = roc_curve(y_bin, score)
    grid = np.unique(np.concatenate([np.linspace(0, 1, 41), [0.001, 0.002, 0.005, 0.01, 0.02, 0.05]]))
    return dict(fpr=[round(float(v), 4) for v in grid], tpr=[round(float(v), 4) for v in np.interp(grid, fpr, tpr)],
                auc=round(float(roc_auc_score(y_bin, score)), 4))


def evaluate(y, proba, tau, classes, b, with_curves=False) -> dict:
    K = len(classes)
    pred, score = decide(proba, tau, b)
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=list(range(K)), zero_division=0)
    pm, rm, fm, _ = precision_recall_fscore_support(y, pred, labels=list(range(K)), average="macro", zero_division=0)
    is_atk = y != b
    out = dict(
        accuracy=round(float(accuracy_score(y, pred)), 4),
        precision=round(float(pm), 4), recall=round(float(rm), 4), f1=round(float(fm), 4),
        f1_weighted=round(float(f1_score(y, pred, average="weighted", zero_division=0)), 4),
        roc_auc=round(float(roc_auc_score(y, proba, multi_class="ovr", average="macro", labels=list(range(K)))), 4),
        false_positive_rate=round(float(np.mean(pred[~is_atk] != b)), 4),
        detection_rate=round(float(np.mean(pred[is_atk] != b)), 4),
        tau=round(float(tau), 4),
        per_class={classes[i]: dict(precision=round(float(p[i]), 4), recall=round(float(r[i]), 4),
                                    f1=round(float(f[i]), 4), support=int(s[i])) for i in range(K)},
    )
    if with_curves:
        out["confusion_matrix"] = confusion_matrix(y, pred, labels=list(range(K))).tolist()
        out["roc"] = _roc_points(is_atk.astype(int), score)
    return out


def _time_single(est, X, n=30) -> float:
    """Mean ms for a single-row predict_proba (what the streaming path pays per event)."""
    est.predict_proba(X[:1])  # warm-up
    t = time.perf_counter()
    for i in range(min(n, len(X))):
        est.predict_proba(X[i:i + 1])
    return (time.perf_counter() - t) / min(n, len(X)) * 1000


def _single_thread(est):
    try:
        if "n_jobs" in est.get_params():
            est.set_params(n_jobs=1)
    except Exception:
        pass
    return est


# ------------------------------------------------------------------ data loading
def load_csv_dataset(path: str, label_col: str = "label", label_map: dict | None = None):
    """Load a labelled CSV (platform feature schema). Returns (DataFrame, dropped_row_count)."""
    df = pd.read_csv(path)
    if label_col not in df.columns:
        raise ValueError(f"label column '{label_col}' not found in {path}")
    lm = {k.lower(): v for k, v in (label_map or {}).items()}
    by_lower = {c.lower(): c for c in CLASSES + ["Zero-Day"]}
    mapped = df[label_col].astype(str).map(lambda v: lm.get(v.lower(), by_lower.get(v.lower())))
    keep = mapped.notna()
    df = df.loc[keep].copy()
    df["label"] = mapped[keep].values
    return df, int((~keep).sum())


def _prepare(cfg: TrainConfig):
    if cfg.dataset == "synthetic":
        df = generate_dataset(cfg.n_samples, seed=cfg.seed, stealth=cfg.stealth)
        dropped = 0
    else:
        df, dropped = load_csv_dataset(cfg.csv_path, label_map=cfg.extra.get("label_map"))
    novel = df[df["label"] == "Zero-Day"].drop(columns="label") if "Zero-Day" in set(df["label"]) else None
    df = df[df["label"] != "Zero-Day"]
    if novel is None and cfg.dataset == "synthetic":
        novel = sample_class("Zero-Day", cfg.novel_n, np.random.default_rng(cfg.seed + 1000), 0.0)
    present = set(df["label"])
    if BENIGN not in present:
        raise ValueError("dataset must contain Benign rows")
    classes = [c for c in CLASSES if c in present]
    y = df["label"].map({c: i for i, c in enumerate(classes)}).to_numpy()
    X = engineer(df.drop(columns="label"))
    Xn = engineer(novel) if novel is not None and len(novel) else None
    return X, y, classes, Xn, dropped


# ------------------------------------------------------------------ main entry point
def train(cfg: TrainConfig | None = None, progress=None) -> ThreatModelBundle:
    cfg = cfg or TrainConfig()
    prog = progress or (lambda stage, frac: None)
    t0 = time.time()
    prog("Preparing data", 0.02)
    X, y, classes, Xn, dropped = _prepare(cfg)
    K, b = len(classes), classes.index(BENIGN)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=cfg.test_size, stratify=y, random_state=cfg.seed)
    log.info("Training on %d rows (%d test), %d classes", len(X_tr), len(X_te), K)
    flag_cols = [FEATURES.index(f) for f in FLAGS]
    candidates = build_candidates(cfg)
    names = list(candidates)

    # ---- stratified k-fold CV, SMOTE inside each training fold only
    oof = {n: np.zeros((len(X_tr), K)) for n in names}
    fold_f1 = {n: [] for n in names}
    skf = StratifiedKFold(n_splits=cfg.cv_folds, shuffle=True, random_state=cfg.seed)
    total_steps = cfg.cv_folds * len(names)
    step = 0
    for fold, (tr, va) in enumerate(skf.split(X_tr, y_tr)):
        Xf, yf = smote(X_tr[tr], y_tr[tr], ratio=cfg.smote_ratio, seed=cfg.seed + fold, round_columns=flag_cols)
        for n in names:
            est = candidates[n]().fit(Xf, yf)
            pv = est.predict_proba(X_tr[va])
            oof[n][va] = pv
            fold_f1[n].append(float(f1_score(y_tr[va], pv.argmax(1), average="macro", zero_division=0)))
            step += 1
            prog(f"Cross-validation fold {fold + 1}/{cfg.cv_folds}: {n}", 0.05 + 0.5 * step / total_steps)
    cv_mean = {n: float(np.mean(v)) for n, v in fold_f1.items()}
    weights = {n: max(cv_mean[n], 1e-3) ** 4 for n in names}
    wsum = sum(weights.values())
    weights = {n: w / wsum for n, w in weights.items()}
    oof_ens = sum(weights[n] * oof[n] for n in names)
    taus = {n: choose_tau(oof[n], y_tr, b, cfg.target_fpr) for n in names}
    taus["ensemble"] = choose_tau(oof_ens, y_tr, b, cfg.target_fpr)

    # ---- final fit on the full (SMOTE-balanced) training set
    prog("Fitting final models", 0.6)
    Xs, ys = smote(X_tr, y_tr, ratio=cfg.smote_ratio, seed=cfg.seed, round_columns=flag_cols)
    members, train_s = {}, {}
    for n in names:
        t = time.time()
        members[n] = _single_thread(candidates[n]().fit(Xs, ys))
        train_s[n] = round(time.time() - t, 2)
    ensemble = ThreatEnsemble(members, weights, classes)

    # ---- hold-out evaluation
    prog("Evaluating on hold-out set", 0.78)
    models_report, roc = {}, {}
    for n in names:
        ev = evaluate(y_te, members[n].predict_proba(X_te), taus[n], classes, b, with_curves=True)
        ev.update(cv_f1_mean=round(cv_mean[n], 4), cv_f1_std=round(float(np.std(fold_f1[n])), 4),
                  infer_ms=round(_time_single(members[n], X_te), 3), train_seconds=train_s[n], weight=round(weights[n], 4))
        roc[n] = ev.pop("roc")
        ev.pop("confusion_matrix")
        models_report[n] = ev
    ens_ev = evaluate(y_te, ensemble.predict_proba(X_te), taus["ensemble"], classes, b, with_curves=True)
    ens_ev.update(infer_ms=round(_time_single(ensemble, X_te), 3), train_seconds=round(sum(train_s.values()), 2),
                  cv_f1_mean=round(float(np.mean([cv_mean[n] for n in names])), 4))
    roc["ensemble"] = ens_ev.pop("roc")
    confusion = ens_ev.pop("confusion_matrix")
    models_report["ensemble"] = ens_ev

    # ---- autoencoder anomaly detector (benign only) + isolation-forest baseline
    prog("Training anomaly detector", 0.88)
    Xb = X_tr[y_tr == b]
    cut = int(0.8 * len(Xb))
    ae = AutoencoderDetector(seed=cfg.seed).fit(Xb[:cut]).calibrate(Xb[cut:], 99.5)
    bundle = ThreatModelBundle(ensemble, ae, classes, taus["ensemble"],
                               baseline=np.median(Xb, axis=0))
    ben_te = X_te[y_te == b]
    atk_te = X_te[y_te != b]
    anomaly_rep = dict(threshold=round(ae.threshold, 5),
                       benign_flag_rate=round(float(np.mean(ae.score(ben_te) >= 1.0)), 4),
                       known_attack_flag_rate=round(float(np.mean(ae.score(atk_te) >= 1.0)), 4))
    hybrid = None
    if Xn is not None:
        Xn = np.asarray(Xn)
        n_ben = ae.score(ben_te)
        n_nov = ae.score(Xn)
        yb = np.r_[np.zeros(len(n_ben)), np.ones(len(n_nov))]
        anomaly_rep["autoencoder_auc_vs_benign"] = round(float(roc_auc_score(yb, np.r_[n_ben, n_nov])), 4)
        iso = IsolationForest(n_estimators=200, random_state=cfg.seed, n_jobs=-1).fit(Xb[:cut])
        anomaly_rep["isolation_forest_auc_vs_benign"] = round(float(roc_auc_score(
            yb, -iso.score_samples(np.vstack([ben_te, Xn])))), 4)
        anomaly_rep["novel_flag_rate"] = round(float(np.mean(n_nov >= 1.0)), 4)
        res_nov, res_ben, res_atk = bundle.classify(Xn), bundle.classify(ben_te), bundle.classify(atk_te)
        atk_true = np.array([classes[i] for i in y_te[y_te != b]])
        hybrid = dict(
            benign_false_positive_rate=round(float(np.mean(np.array(res_ben["labels"]) != BENIGN)), 4),
            known_attack_detection_rate=round(float(np.mean(np.array(res_atk["labels"]) != BENIGN)), 4),
            known_attack_type_accuracy=round(float(np.mean(np.array(res_atk["labels"]) == atk_true)), 4),
            zero_day_detected_as_threat=round(float(np.mean(np.array(res_nov["labels"]) != BENIGN)), 4),
            zero_day_labelled_zero_day=round(float(np.mean(np.array(res_nov["labels"]) == "Zero-Day")), 4),
            zero_day_samples=int(len(Xn)), unknown_conf=bundle.unknown_conf,
        )
        # The label "Zero-Day" cannot come from the anomaly score alone (attacks are anomalous by nature); it comes
        # from the classifier being unsure. This sweep shows the unavoidable trade-off for transparency.
        sweep = []
        for uc in (0.5, 0.6, 0.7, 0.8, 0.9):
            la, ln = np.array(bundle.classify(atk_te, uc)["labels"]), np.array(bundle.classify(Xn, uc)["labels"])
            sweep.append(dict(unknown_conf=uc, known_type_accuracy=round(float(np.mean(la == atk_true)), 4),
                              known_labelled_zero_day=round(float(np.mean(la == "Zero-Day")), 4),
                              novel_labelled_zero_day=round(float(np.mean(ln == "Zero-Day")), 4)))
        hybrid["unknown_conf_sweep"] = sweep

    rf = members.get("random_forest")
    importances = []
    if rf is not None:
        order = np.argsort(-rf.feature_importances_)[:15]
        importances = [dict(feature=FEATURES[i], importance=round(float(rf.feature_importances_[i]), 4)) for i in order]

    synthetic = cfg.dataset == "synthetic"
    bundle.report = dict(
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        dataset=dict(name="synthetic-flows-v1 (NSL-KDD/CICIDS-style simulation)" if synthetic else str(cfg.csv_path),
                     synthetic=synthetic, rows=int(len(X)), train_rows=int(len(X_tr)), test_rows=int(len(X_te)),
                     dropped_rows=dropped, class_counts={classes[i]: int((y == i).sum()) for i in range(K)}),
        config={k: v for k, v in asdict(cfg).items() if k != "extra"},
        classes=classes, features=FEATURES,
        decision=dict(target_fpr=cfg.target_fpr, tau=round(taus["ensemble"], 4),
                      weights={n: round(w, 4) for n, w in weights.items()}),
        models=models_report, roc=roc, confusion_matrix=confusion, anomaly=anomaly_rep, hybrid=hybrid,
        feature_importance=importances, model_info={k: v for k, v in MODEL_INFO.items() if k in models_report or k in ("ensemble", "autoencoder")},
        environment=dict(python=platform.python_version(), sklearn=sklearn.__version__,
                         xgboost="xgboost" in members, lightgbm="lightgbm" in members),
        training_seconds=round(time.time() - t0, 1),
    )
    prog("Done", 1.0)
    log.info("Training finished in %.1fs; ensemble F1=%.4f FPR=%.4f", time.time() - t0, ens_ev["f1"], ens_ev["false_positive_rate"])
    return bundle
