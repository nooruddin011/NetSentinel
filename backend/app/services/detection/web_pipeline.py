"""Web detection pipeline: signature rules + behaviour tracking + text model -> verdict, severity, explanation."""
from __future__ import annotations

from app.detectors.webrules import scan
from app.ml.webmodel import request_text
from app.services.connectors.behaviour import BehaviourConfig, BehaviourTracker
from app.services.detection.severity import score_risk
from app.services.detection.webfuse import fuse


class WebDetectionPipeline:
    def __init__(self, text_model, critical_assets=(), behaviour: BehaviourConfig | None = None, report=None):
        self.model = text_model
        self.critical_assets = list(critical_assets)
        self.tracker = BehaviourTracker(behaviour)
        self.report = report or {}

    def set_model(self, text_model, report=None):
        self.model, self.report = text_model, report or {}

    def analyze_batch(self, events: list, source_id, protected_ip: str = "", repeat_counts: dict | None = None) -> list:
        """events: normalised web events (see webevent). Returns one detection dict per event, in input order."""
        if not events:
            return []
        texts = [request_text(e["path"], e["query"]) for e in events]
        top = self.model.top_attack(texts)                       # one vectorised call for the whole batch
        dets = [None] * len(events)
        for i in sorted(range(len(events)), key=lambda k: events[k]["ts"]):   # behaviour needs time order
            e = events[i]
            hits = scan(e) + self.tracker.observe(source_id, e)
            fused = fuse(hits, top[i])
            if fused is None:
                dets[i] = dict(verdict="benign", attack_type=None, confidence=round(1.0 - top[i][1], 4), severity=None, risk_score=0.0,
                               sources=[], signature_hits=[], ml_label="Benign", detectors_agree=None, attack_score=round(top[i][1], 4),
                               anomaly_ratio=0.0, class_probs=[], explanation=None)
                continue
            attack = fused["attack_type"]
            risk, sev = score_risk(attack, fused["confidence"], protected_ip, self.critical_assets,
                                   (repeat_counts or {}).get(e["src_ip"], 0), corroborated=fused["corroborated"])
            dets[i] = dict(verdict="threat", attack_type=attack, confidence=round(fused["confidence"], 4), severity=sev, risk_score=risk,
                           sources=fused["sources"], signature_hits=[h.rule_id for h in hits if h.attack_type == attack],
                           ml_label=top[i][0], detectors_agree=fused["corroborated"], attack_score=round(top[i][1], 4), anomaly_ratio=0.0,
                           class_probs=[dict(label=top[i][0], p=round(top[i][1], 4))],
                           explanation=self._explain(attack, hits, top[i]))
        return dets

    @staticmethod
    def _explain(attack, hits, ml) -> list:
        items = []
        for h in hits:
            if h.attack_type == attack:
                feat = "behaviour" if h.kind == "behaviour" else ("User-Agent" if h.rule_id == "WEB-TOOL-001" else "request")
                items.append((h.description, feat, (h.evidence or "")[:80], h.confidence))
        if ml[0] == attack and ml[1] >= 0.5:
            items.append((f"Text model: the request resembles {attack}", "text model", f"{ml[1]:.0%} probability", ml[1]))
        total = sum(w for *_x, w in items) or 1.0
        return [dict(factor=f, impact=round(w, 4), share=round(w / total, 3), feature=feat, value=val) for f, feat, val, w in sorted(items, key=lambda t: -t[3])]
