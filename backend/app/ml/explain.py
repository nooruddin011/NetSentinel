"""Model-agnostic local explanations (grouped occlusion) -- an offline substitute for SHAP.

For a flagged event we replace one *feature group* at a time with its benign-median value and
measure how much the predicted-class probability drops. Groups (e.g. all volume features) are
occluded together because derived features are strongly correlated with their raw inputs.
"""
from __future__ import annotations

import numpy as np

from app.ml.schema import FEATURES

# label -> (primary raw feature shown to the analyst, all features in the group)
GROUPS = {
    "Traffic volume": ("src_bytes", ["src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "bytes_per_sec", "pkts_per_sec", "avg_pkt_size", "byte_ratio"]),
    "Connection duration": ("duration", ["duration"]),
    "Protocol / port": ("dst_port", ["is_tcp", "is_udp", "is_icmp", "dst_port"]),
    "Connections from source": ("conn_count_src", ["conn_count_src"]),
    "Ports / hosts contacted": ("distinct_dst_ports", ["distinct_dst_ports", "distinct_dst_hosts"]),
    "Failed logins": ("failed_logins", ["failed_logins"]),
    "Error / SYN ratio": ("syn_ratio", ["error_rate", "syn_ratio"]),
    "Payload size": ("payload_len", ["payload_len"]),
    "Payload entropy": ("payload_entropy", ["payload_entropy"]),
    "Special characters": ("special_char_ratio", ["special_char_ratio"]),
    "SQL keywords": ("sql_kw_count", ["sql_kw_count"]),
    "Script patterns": ("script_tag_count", ["script_tag_count"]),
    "URL reputation": ("domain_age_days", ["has_ip_url", "phish_kw_count", "domain_age_days"]),
    "TLS certificate": ("cert_mismatch", ["cert_mismatch"]),
    "Latency vs baseline": ("latency_ratio", ["latency_ratio"]),
    "Off-hours activity": ("off_hours", ["off_hours"]),
    "Unusual destination": ("unusual_dest", ["unusual_dest"]),
    "SMB write rate": ("smb_write_rate", ["smb_write_rate"]),
    "Beacon regularity": ("beacon_interval_std", ["beacon_interval_std"]),
    "DNS query rate": ("dns_query_rate", ["dns_query_rate"]),
}
_GROUP_IDX = {name: [FEATURES.index(f) for f in feats] for name, (_, feats) in GROUPS.items()}


def _fmt(v):
    v = float(v)
    return int(v) if abs(v - round(v)) < 1e-9 else round(v, 3)


def explain_class(ensemble, x_row: np.ndarray, class_idx: int, baseline: np.ndarray, raw: dict, top_k: int = 5) -> list:
    """Top feature groups pushing the prediction toward `class_idx` (positive impact = supports the verdict)."""
    names = list(GROUPS)
    X = np.tile(x_row, (len(names), 1))
    for r, name in enumerate(names):
        X[r, _GROUP_IDX[name]] = baseline[_GROUP_IDX[name]]
    base_p = ensemble.predict_proba(x_row.reshape(1, -1))[0, class_idx]
    drops = base_p - ensemble.predict_proba(X)[:, class_idx]
    order = np.argsort(-drops)[:top_k]
    total = float(np.clip(drops, 0, None).sum()) or 1.0
    out = []
    for i in order:
        if drops[i] <= 1e-4:
            continue
        primary = GROUPS[names[i]][0]
        out.append(dict(factor=names[i], impact=round(float(drops[i]), 4), share=round(float(max(drops[i], 0)) / total, 3),
                        feature=primary, value=_fmt(raw.get(primary, 0.0))))
    return out


def explain_anomaly(detector, x_row: np.ndarray, raw: dict, top_k: int = 5) -> list:
    """Feature groups with the largest reconstruction error (what made this traffic 'unfamiliar')."""
    fe = detector.feature_errors(x_row.reshape(1, -1))[0]
    names = list(GROUPS)
    scores = np.array([fe[_GROUP_IDX[n]].sum() for n in names])
    total = float(scores.sum()) or 1.0
    out = []
    for i in np.argsort(-scores)[:top_k]:
        primary = GROUPS[names[i]][0]
        out.append(dict(factor=names[i], impact=round(float(scores[i]), 4), share=round(float(scores[i]) / total, 3),
                        feature=primary, value=_fmt(raw.get(primary, 0.0))))
    return out
