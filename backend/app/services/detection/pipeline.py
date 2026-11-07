"""Hybrid detection pipeline: signature rules + supervised ensemble + autoencoder anomaly detection,
fused into one verdict with severity scoring, a prediction cache and local explanations."""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict

import numpy as np

from app.detectors.signature import SignatureEngine
from app.ml.explain import explain_anomaly, explain_class
from app.ml.payload import payload_features
from app.ml.schema import clean_record, engineer
from app.models.attacks import BENIGN
from app.services.detection.severity import score_risk
from app.utils.net import safe_ip

_PAYLOAD_KEYS = ["payload_len", "payload_entropy", "special_char_ratio", "sql_kw_count", "script_tag_count",
                 "has_ip_url", "phish_kw_count"]


def normalize_event(raw: dict) -> dict:
    """Clean one incoming event. Text payload (if any) always overrides client-supplied payload features,
    so a caller cannot hide an injection by sending `sql_kw_count: 0`."""
    ev = dict(raw)
    payload = ev.get("payload_sample")
    payload = payload[:4096] if isinstance(payload, str) else ""  # NaN/None/numbers from CSV cells are "no payload"
    if payload:
        ev.update(payload_features(payload))
    feats = clean_record(ev)
    try:
        ts = float(ev.get("ts") or ev.get("timestamp") or time.time())
    except (TypeError, ValueError):
        ts = time.time()
    proto = str(ev.get("protocol") or ("TCP" if feats["is_tcp"] else "UDP" if feats["is_udp"] else "ICMP")).upper()[:8]
    return dict(ts=ts, src_ip=safe_ip(ev.get("src_ip"), "0.0.0.0"), dst_ip=safe_ip(ev.get("dst_ip"), "0.0.0.0"),
                protocol=proto, payload_sample=payload[:500], features=feats)


class _LRU:
    def __init__(self, size):
        self.size, self._d, self._lock = size, OrderedDict(), threading.Lock()
        self.hits = self.misses = 0

    def get(self, k):
        with self._lock:
            if k in self._d:
                self._d.move_to_end(k)
                self.hits += 1
                return self._d[k]
            self.misses += 1

    def put(self, k, v):
        with self._lock:
            self._d[k] = v
            self._d.move_to_end(k)
            while len(self._d) > self.size:
                self._d.popitem(last=False)

    def clear(self):
        with self._lock:
            self._d.clear()


class DetectionPipeline:
    def __init__(self, bundle, critical_assets=(), cache_size=4096):
        self.bundle = bundle
        self.sig = SignatureEngine()
        self.critical_assets = list(critical_assets)
        self._cache = _LRU(cache_size)

    def set_bundle(self, bundle):
        self.bundle = bundle  # atomic reference swap; in-flight calls finish on the old bundle
        self._cache.clear()

    def cache_stats(self):
        h, m = self._cache.hits, self._cache.misses
        return dict(hits=h, misses=m, hit_rate=round(h / (h + m), 3) if h + m else 0.0)

    # --------------------------------------------------------------- ML with cache
    def _ml(self, X: np.ndarray) -> list:
        bundle = self.bundle
        keys = [hashlib.blake2b(row.tobytes(), digest_size=12).digest() for row in X]
        out, todo = [None] * len(X), []
        for i, k in enumerate(keys):
            hit = self._cache.get(k)
            if hit is None:
                todo.append(i)
            else:
                out[i] = hit
        if todo:
            res = bundle.classify(X[todo])
            for j, i in enumerate(todo):
                top = np.argsort(-res["proba"][j])[:3]
                item = dict(label=res["labels"][j], confidence=float(res["confidence"][j]),
                            attack_score=float(res["attack_score"][j]), anomaly_ratio=float(res["anomaly_ratio"][j]),
                            unknown=bool(res["unknown"][j]), label_idx=int(res["label_idx"][j]),
                            class_probs=[dict(label=bundle.classes[t], p=round(float(res["proba"][j][t]), 4)) for t in top])
                out[i] = item
                self._cache.put(keys[i], item)
        return out

    # --------------------------------------------------------------- fusion
    def _fuse(self, ev, ml, hits, repeat_count=0):
        ml_label = ml["label"]
        sig = max(hits, key=lambda h: h.confidence) if hits else None
        sources = []
        if sig:
            sources += [f"signature:{h.rule_id}" for h in hits]
        if ml_label != BENIGN:
            sources.append("anomaly" if ml_label == "Zero-Day" else "ensemble")
        if sig is None and ml_label == BENIGN:
            return dict(verdict="benign", attack_type=None, confidence=round(ml["confidence"], 4), severity=None,
                        risk_score=0.0, sources=[], signature_hits=[], ml_label=ml_label, detectors_agree=None,
                        attack_score=round(ml["attack_score"], 4), anomaly_ratio=round(ml["anomaly_ratio"], 3),
                        class_probs=ml["class_probs"])
        if sig and ml_label == sig.attack_type:
            attack, conf, agree = sig.attack_type, 1 - (1 - sig.confidence) * (1 - ml["confidence"]), True
        elif sig and (ml_label == BENIGN or sig.confidence >= ml["confidence"]):
            attack, conf, agree = sig.attack_type, sig.confidence, False if ml_label != BENIGN else None
        else:
            attack, conf, agree = ml_label, ml["confidence"], None if not sig else False
        conf = float(min(conf, 0.995))
        risk, sev = score_risk(attack, conf, ev["dst_ip"], self.critical_assets, repeat_count,
                               corroborated=bool(agree))
        return dict(verdict="threat", attack_type=attack, confidence=round(conf, 4), severity=sev, risk_score=risk,
                    sources=sources, signature_hits=[h.rule_id for h in hits], ml_label=ml_label, detectors_agree=agree,
                    attack_score=round(ml["attack_score"], 4), anomaly_ratio=round(ml["anomaly_ratio"], 3),
                    class_probs=ml["class_probs"])

    # --------------------------------------------------------------- public API
    def explain(self, features: dict, attack_type: str) -> list:
        """Local explanation for a stored/flagged event (computed on demand, never trusted from clients)."""
        bundle = self.bundle
        X = engineer([features])
        if attack_type == "Zero-Day" or attack_type not in bundle.classes:
            return explain_anomaly(bundle.anomaly, X[0], features)
        return explain_class(bundle.ensemble, X[0], bundle.classes.index(attack_type), bundle.baseline, features)

    def analyze_many(self, events: list, repeat_counts=None, explain_top: int = 0) -> list:
        """Batch analysis of already-normalised events. Explanations are computed only for the
        `explain_top` highest-risk threats (the rest can be explained on demand)."""
        if not events:
            return []
        X = engineer([e["features"] for e in events])
        mls = self._ml(X)
        results = []
        for i, ev in enumerate(events):
            hits = self.sig.scan({**ev["features"], "payload_sample": ev["payload_sample"]})
            det = self._fuse(ev, mls[i], hits, (repeat_counts or {}).get(ev["src_ip"], 0))
            det["explanation"] = None
            results.append(det)
        if explain_top:
            order = sorted((i for i, d in enumerate(results) if d["verdict"] == "threat"),
                           key=lambda i: -results[i]["risk_score"])[:explain_top]
            for i in order:
                results[i]["explanation"] = self.explain(events[i]["features"], results[i]["attack_type"])
        return results

    def analyze(self, ev: dict, repeat_count: int = 0, explain: bool = True) -> dict:
        det = self.analyze_many([ev], {ev["src_ip"]: repeat_count})[0]
        if explain and det["verdict"] == "threat":
            det["explanation"] = self.explain(ev["features"], det["attack_type"])
        return det
