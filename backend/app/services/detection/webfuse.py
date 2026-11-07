"""Fusion of web-detector evidence into one verdict.

Evidence comes from three independent layers: signature rules, the behaviour tracker and the text model.
For each attack type the confidences are combined with a noisy-OR (independent evidence strengthens, it never
weakens), then the best type wins. When two types are close, the more severe one wins (a request that is both
"reads /etc/passwd" and "runs `cat`" is a command injection first); the nudge is 1.5 points per severity level,
so it only breaks near-ties.
"""
from __future__ import annotations

from app.models.attacks import ATTACKS

SEV_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
ALERT_THRESHOLD = 0.75   # combined confidence needed to call a request an attack
ML_FLOOR = 0.50          # text-model probabilities below this are ignored as evidence
ML_CAP = 0.97


def fuse(hits, ml=None, threshold=ALERT_THRESHOLD):
    """hits: WebHit list (signature + behaviour). ml: (attack_class, probability) or None.

    Returns None (benign) or dict(attack_type, confidence, sources, corroborated, scores)."""
    cands = {}
    for h in hits:
        cands.setdefault(h.attack_type, []).append((h.confidence, f"{h.kind}:{h.rule_id}", h.kind))
    if ml and ml[0] in ATTACKS and ml[1] >= ML_FLOOR:
        cands.setdefault(ml[0], []).append((min(ML_CAP, ml[1] * ML_CAP), "text-model", "model"))
    if not cands:
        return None
    scores = {}
    for attack, lst in cands.items():
        miss = 1.0
        for conf, _src, _kind in lst:
            miss *= 1.0 - conf
        scores[attack] = 1.0 - miss
    best = max(scores, key=lambda a: scores[a] + 0.015 * SEV_RANK.get(ATTACKS[a]["severity"], 0))
    if scores[best] < threshold:
        return None
    kinds = {k for _c, _s, k in cands[best]}
    return dict(attack_type=best, confidence=min(0.995, scores[best]), sources=[s for _c, s, _k in cands[best]],
                corroborated=len(kinds) >= 2, scores={a: round(v, 3) for a, v in scores.items()})
