"""Web-request text model: character n-gram TF-IDF + logistic regression.

Why character n-grams: attack payloads are made of distinctive *fragments* ("' or ", "union sel", "<script", "../..", ";cat ")
that survive case changes, extra spaces and partial encoding, unlike whole-word features. The model complements the
signature rules by recognising variants the rules do not list. It is evaluated on payload *families it never saw*.
"""
from __future__ import annotations

import logging
import re as _re
import time
from datetime import datetime, timezone

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import cross_val_predict

from app.detectors.webrules import scan
from app.ml.payload import decode_payload
from app.ml.webcorpus import BENIGN, CLASSES, FAMILIES, HOLDOUT, generate
from app.services.connectors.webevent import normalize_policy, normalize_web_event
from app.services.detection.webfuse import ALERT_THRESHOLD, fuse

log = logging.getLogger(__name__)
ATTACK_CLASSES = [c for c in CLASSES if c != BENIGN]


def request_text(path: str, query: str) -> str:
    return decode_payload(path + (("?" + query) if query else "")).lower()[:600]


class WebTextModel:
    def __init__(self, vectorizer, clf, classes):
        self.vectorizer, self.clf, self.classes = vectorizer, clf, list(classes)
        self.benign_idx = self.classes.index(BENIGN)

    def predict_proba(self, texts) -> np.ndarray:
        return self.clf.predict_proba(self.vectorizer.transform(texts))

    def top_attack(self, texts):
        """(attack_class, probability) per text; probability is P(that attack class)."""
        P = self.predict_proba(texts)
        A = P.copy(); A[:, self.benign_idx] = -1
        idx = A.argmax(axis=1)
        return [(self.classes[i], float(P[r, i])) for r, i in enumerate(idx)]


def _fit(rows, seed):
    texts = [request_text(p, q) for p, q, *_ in rows]
    y = [r[2] for r in rows]
    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=80000, lowercase=False, dtype=np.float32)
    X = vec.fit_transform(texts)
    clf = LogisticRegression(C=10.0, max_iter=400, class_weight="balanced", random_state=seed).fit(X, y)
    return WebTextModel(vec, clf, clf.classes_)


def _event(path, query):
    ev, _ = normalize_web_event({"src_ip": "198.51.100.1", "path": path, "query": query}, normalize_policy({}))
    return ev


def _label(fused):
    return fused["attack_type"] if fused and fused["attack_type"] in ATTACK_CLASSES else BENIGN


def _metrics(y_true, y_pred):
    labels = CLASSES
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    benign = [i for i, t in enumerate(y_true) if t == BENIGN]
    attacks = [i for i, t in enumerate(y_true) if t != BENIGN]
    return dict(
        accuracy=round(float(np.mean([a == b for a, b in zip(y_true, y_pred)])), 4),
        false_positive_rate=round(float(np.mean([y_pred[i] != BENIGN for i in benign])), 4) if benign else None,
        detection_rate=round(float(np.mean([y_pred[i] != BENIGN for i in attacks])), 4) if attacks else None,
        per_class={c: dict(precision=round(float(p[i]), 4), recall=round(float(r[i]), 4), f1=round(float(f[i]), 4), support=int(s[i])) for i, c in enumerate(labels)})


def structure_leak_audit(rows) -> dict:
    """Can a model tell attacks from benign requests using ONLY request structure (path, parameter NAMES, extras) and no payload?

    It must not: if it can, the corpus has a generator artefact (like "Submit=Submit only appears on attacks") and the
    payload model would learn the artefact instead of attacks. Reports cross-validated ROC-AUC (0.5 = no leak)."""
    rows = [r for r in rows if r[1]]  # requests without a query string cannot carry a payload; comparing them would be unfair
    texts = []
    for p, q, *_ in rows:
        names = " ".join(k for k, sep, _v in (part.partition("=") for part in q.split("&")) if sep and _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k))
        marks = " ".join(m for m in ("Submit=Submit", "Login=Login", "lang=en", "[REDACTED]") if m in q)
        texts.append(f"{p} {names} {marks}")
    y = [0 if r[2] == BENIGN else 1 for r in rows]
    X = TfidfVectorizer(analyzer="word", token_pattern=r"\S+", min_df=2).fit_transform(texts)
    proba = cross_val_predict(LogisticRegression(max_iter=300), X, y, cv=3, method="predict_proba")[:, 1]
    return dict(structure_only_auc=round(float(roc_auc_score(y, proba)), 3), note="0.5 means request structure carries no signal (good)")


def train_web_model(n_per_attack=1500, n_benign=9000, seed=7, evaluate=True, progress=None):
    """Train the production model on ALL families, and (optionally) run the held-out-family experiment.

    Returns (model, report)."""
    prog = progress or (lambda *_: None)
    t0 = time.time()
    prog("Generating corpus", 0.05)
    rows = generate(n_per_attack, n_benign, seed)
    report = dict(alert_threshold=ALERT_THRESHOLD, created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), synthetic=True,
                  corpus=dict(per_attack=n_per_attack, benign=n_benign, families={c: list(f) for c, f in FAMILIES.items()}), classes=CLASSES)
    if evaluate:
        # --- experiment 1: honest generalisation. Train WITHOUT the held-out families, test on ONLY those families.
        prog("Held-out family experiment", 0.2)
        held = {f for fams in HOLDOUT.values() for f in fams}
        train_rows = [r for r in rows if r[3] == "benign" or r[3] not in held]
        seen_model = _fit(train_rows, seed)
        test = [r for r in generate(400, 0, seed + 101, train_families=False) if r[2] != BENIGN] + \
               [r for r in generate(0, 2500, seed + 202) if r[2] == BENIGN]
        texts = [request_text(p, q) for p, q, *_ in test]
        truth = [r[2] for r in test]
        top = seen_model.top_attack(texts)
        events = [_event(p, q) for p, q, *_ in test]
        sig_pred = [_label(fuse(scan(e), None)) for e in events]                         # rules alone
        ml_pred = [_label(fuse([], t)) for t in top]                                      # text model alone
        comb_pred = [_label(fuse(scan(e), t)) for e, t in zip(events, top)]               # the real pipeline fusion
        fam_recall = {}
        for name, pred in (("signatures_only", sig_pred), ("text_model_only", ml_pred), ("combined", comb_pred)):
            for (cls, fam) in {(r[2], r[3]) for r in test if r[2] != BENIGN}:
                idx = [i for i, r in enumerate(test) if r[2] == cls and r[3] == fam]
                fam_recall.setdefault(f"{cls} / {fam}", {})[name] = round(float(np.mean([pred[i] == cls for i in idx])), 4)
        report["held_out_families"] = dict(
            description="Models trained WITHOUT these payload families, tested on them (plus fresh benign traffic).",
            held_out={c: list(f) for c, f in HOLDOUT.items()}, test_size=len(test),
            signatures_only=_metrics(truth, sig_pred), text_model_only=_metrics(truth, ml_pred), combined=_metrics(truth, comb_pred),
            recall_by_family=dict(sorted(fam_recall.items())))
        # --- experiment 2: ordinary in-distribution split (all families seen in training)
        prog("In-distribution split", 0.5)
        cut = int(0.8 * len(rows))
        m2 = _fit(rows[:cut], seed)
        te = rows[cut:]
        tt = m2.top_attack([request_text(p, q) for p, q, *_ in te])
        pred2 = [_label(fuse(scan(_event(r[0], r[1])), t)) for r, t in zip(te, tt)]
        report["in_distribution"] = dict(description="Random 80/20 split; every payload family is seen in training. Optimistic: the corpus is templated, so near-perfect scores here say little.",
                                         test_size=len(te), **_metrics([r[2] for r in te], pred2))
    report["leak_audit"] = structure_leak_audit(rows)
    prog("Training final model", 0.7)
    model = _fit(rows, seed)
    report["training_seconds"] = round(time.time() - t0, 1)
    prog("Done", 1.0)
    return model, report
