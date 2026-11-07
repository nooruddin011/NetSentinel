"""Threat severity scoring: base severity of the attack class, scaled by confidence and context."""
from __future__ import annotations

import math

from app.models.attacks import ATTACKS, SEVERITY_BASE_SCORE


def risk_label(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def score_risk(attack_type: str, confidence: float, dst_ip: str = "", critical_assets=(),
               repeat_count: int = 0, corroborated: bool = False):
    """Return (risk 0-100, label). Components are additive so the score is easy to explain in a viva:
    base(class) x (0.55 + 0.45*confidence) + critical-asset bonus + repetition bonus + corroboration bonus."""
    base = SEVERITY_BASE_SCORE[ATTACKS.get(attack_type, ATTACKS["Zero-Day"])["severity"]]
    score = base * (0.55 + 0.45 * max(0.0, min(1.0, confidence)))
    if dst_ip and dst_ip in set(critical_assets):
        score += 8
    score += min(8.0, 2.0 * math.log2(1 + max(0, repeat_count)))
    if corroborated:
        score += 5
    score = max(0.0, min(100.0, score))
    return round(score, 1), risk_label(score)
