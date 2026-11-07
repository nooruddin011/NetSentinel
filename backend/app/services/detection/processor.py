"""EventProcessor: normalise -> analyse -> persist -> notify. The single entry point for every event
source (live simulator, attack lab, API, file upload)."""
from __future__ import annotations

import logging
import time
from collections import Counter

import numpy as np
import pandas as pd

from app.models.attacks import BENIGN
from app.services.detection.pipeline import DetectionPipeline, normalize_event
from app.services.ingestion import loader

log = logging.getLogger(__name__)
_CHUNK = 2000


class EventProcessor:
    def __init__(self, repo, pipeline: DetectionPipeline, settings, notifier=None):
        self.repo, self.pipeline, self.settings, self.notifier = repo, pipeline, settings, notifier

    @staticmethod
    def public_event(ev, det, ids, origin):
        f = ev["features"]
        return dict(id=ids["event_id"], ts=ev["ts"], src_ip=ev["src_ip"], dst_ip=ev["dst_ip"], protocol=ev["protocol"],
                    dst_port=int(f["dst_port"]), bytes=float(f["src_bytes"] + f["dst_bytes"]), verdict=det["verdict"],
                    attack_type=det["attack_type"], severity=det["severity"], risk_score=det["risk_score"],
                    confidence=det["confidence"], sources=det["sources"], alert_id=ids["alert_id"],
                    alert_is_new=ids["alert_is_new"], blocked=ids["blocked"], origin=origin,
                    payload_sample=ev["payload_sample"][:120])

    def process(self, raw: dict, origin: str = "stream") -> dict:
        ev = normalize_event(raw)
        repeat = self.repo.recent_alert_count(ev["src_ip"], ev["ts"] - 3600)
        det = self.pipeline.analyze(ev, repeat_count=repeat)
        ids = self.repo.record_detection(ev, det, origin=origin, dedupe_window=self.settings.dedupe_window_seconds)
        out = self.public_event(ev, det, ids, origin)
        out["explanation"] = det.get("explanation")
        out["class_probs"] = det.get("class_probs")
        out["detectors_agree"] = det.get("detectors_agree")
        if ids["alert_is_new"] and self.notifier:
            self.notifier.notify(dict(det, src_ip=ev["src_ip"], dst_ip=ev["dst_ip"]))
        return out

    # ------------------------------------------------------------------ batch (uploads)
    def process_dataframe(self, df: pd.DataFrame, job_id: int, origin: str = "upload") -> dict:
        t0 = time.time()
        n = len(df)
        ts = loader.parse_timestamps(df, fallback=time.time())
        df = loader.enrich_windows(df.copy(), ts)
        missing = loader.missing_columns_report(df)
        truth = None
        if "label" in df.columns:
            truth = df["label"].map(loader.map_label)
        raws = df.to_dict("records")
        events = []
        for i, r in enumerate(raws):
            r["ts"] = float(ts[i])
            events.append(normalize_event(r))
        dets = []
        for s in range(0, n, _CHUNK):
            dets += self.pipeline.analyze_many(events[s:s + _CHUNK], explain_top=0)
        # Explanations for the 100 highest-risk threats (others are explained on demand).
        top = sorted((i for i, d in enumerate(dets) if d["verdict"] == "threat"), key=lambda i: -dets[i]["risk_score"])[:100]
        for i in top:
            dets[i]["explanation"] = self.pipeline.explain(events[i]["features"], dets[i]["attack_type"])
        n_alerts, n_new = self.repo.record_bulk(list(zip(events, dets)), origin=origin, job_id=job_id,
                                                dedupe_window=self.settings.dedupe_window_seconds)
        threats = [d for d in dets if d["verdict"] == "threat"]
        by_type = Counter(d["attack_type"] for d in threats)
        by_sev = Counter(d["severity"] for d in threats)
        src = Counter(e["src_ip"] for e, d in zip(events, dets) if d["verdict"] == "threat")
        summary = dict(rows=n, flagged=len(threats), benign=n - len(threats), alerts_created=n_new,
                       by_attack=dict(by_type.most_common()), by_severity=dict(by_sev),
                       top_sources=[dict(ip=k, events=v) for k, v in src.most_common(8)],
                       columns_missing=missing, seconds=round(time.time() - t0, 2),
                       rows_per_second=round(n / max(time.time() - t0, 1e-6)))
        if truth is not None and truth.notna().sum() > 0:
            summary["evaluation"] = self._evaluate(truth, [d["attack_type"] or BENIGN for d in dets])
        return summary

    @staticmethod
    def _evaluate(truth: pd.Series, pred: list) -> dict:
        mask = truth.notna().to_numpy()
        y = np.array(truth[mask])
        p = np.array(pred)[mask]
        classes = sorted(set(y) | set(p))
        per = {}
        for c in classes:
            tp = int(((y == c) & (p == c)).sum()); fp = int(((y != c) & (p == c)).sum()); fn = int(((y == c) & (p != c)).sum())
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            per[c] = dict(precision=round(prec, 4), recall=round(rec, 4),
                          f1=round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0, support=int((y == c).sum()))
        is_atk = y != BENIGN
        return dict(labelled_rows=int(mask.sum()), unmapped_labels=int((~mask).sum()), accuracy=round(float((y == p).mean()), 4),
                    detection_rate=round(float((p[is_atk] != BENIGN).mean()), 4) if is_atk.any() else None,
                    false_positive_rate=round(float((p[~is_atk] != BENIGN).mean()), 4) if (~is_atk).any() else None,
                    per_class=per)
