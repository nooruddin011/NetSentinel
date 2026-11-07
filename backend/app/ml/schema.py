"""Feature schema: the single source of truth for what the models consume.

Raw features come from flows/uploads; derived features are always recomputed so training,
live detection and uploads can never disagree.
"""
from __future__ import annotations

import math

import numpy as np
import pandas as pd

RAW_FEATURES = [
    "duration", "is_tcp", "is_udp", "is_icmp", "dst_port",
    "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
    "conn_count_src", "distinct_dst_ports", "distinct_dst_hosts",
    "failed_logins", "error_rate", "syn_ratio",
    "payload_len", "payload_entropy", "special_char_ratio", "sql_kw_count", "script_tag_count",
    "has_ip_url", "phish_kw_count", "domain_age_days", "cert_mismatch", "latency_ratio",
    "off_hours", "unusual_dest", "smb_write_rate", "beacon_interval_std", "dns_query_rate",
]
DERIVED_FEATURES = ["bytes_per_sec", "pkts_per_sec", "avg_pkt_size", "byte_ratio"]
FEATURES = RAW_FEATURES + DERIVED_FEATURES

# Defaults describe one coherent, ordinary HTTPS page load. They are used when an event/upload lacks a column,
# so missing data looks "typical" rather than anomalous.
DEFAULTS = dict(
    duration=0.5, is_tcp=1.0, is_udp=0.0, is_icmp=0.0, dst_port=443.0,
    src_bytes=700.0, dst_bytes=5000.0, src_pkts=2.0, dst_pkts=8.0,
    conn_count_src=3.0, distinct_dst_ports=1.0, distinct_dst_hosts=1.0,
    failed_logins=0.0, error_rate=0.03, syn_ratio=0.12,
    payload_len=0.0, payload_entropy=0.0, special_char_ratio=0.0, sql_kw_count=0.0, script_tag_count=0.0,
    has_ip_url=0.0, phish_kw_count=0.0, domain_age_days=1800.0, cert_mismatch=0.0, latency_ratio=1.0,
    off_hours=0.0, unusual_dest=0.0, smb_write_rate=0.0, beacon_interval_std=80.0, dns_query_rate=1.6,
)
FLAGS = {"is_tcp", "is_udp", "is_icmp", "has_ip_url", "cert_mismatch", "off_hours", "unusual_dest"}
RATIOS = {"error_rate", "syn_ratio", "special_char_ratio"}
LOG_FEATURES = [
    "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "conn_count_src", "distinct_dst_ports",
    "distinct_dst_hosts", "failed_logins", "payload_len", "domain_age_days", "smb_write_rate",
    "beacon_interval_std", "dns_query_rate", "bytes_per_sec", "pkts_per_sec", "avg_pkt_size", "byte_ratio",
    "sql_kw_count", "script_tag_count", "phish_kw_count",
]
_LOG_IDX = [FEATURES.index(f) for f in LOG_FEATURES]
_MAX = 1e12


def to_frame(data) -> pd.DataFrame:
    """Accept a DataFrame or list of dicts; return a clean numeric frame with every RAW feature.

    Returns the frame with attribute-free semantics; use `missing_columns` to learn which
    features were absent from the input.
    """
    df = data.copy() if isinstance(data, pd.DataFrame) else pd.DataFrame(list(data))
    if "protocol" in df.columns:
        proto = df["protocol"].astype(str).str.upper()
        for col, name in (("is_tcp", "TCP"), ("is_udp", "UDP"), ("is_icmp", "ICMP")):
            if col not in df.columns:
                df[col] = (proto == name).astype(float)
    out = pd.DataFrame(index=df.index)
    for col in RAW_FEATURES:
        if col in df.columns:
            s = pd.to_numeric(df[col], errors="coerce")
        else:
            s = pd.Series(np.nan, index=df.index)
        out[col] = s.replace([np.inf, -np.inf], np.nan).fillna(DEFAULTS[col]).clip(lower=0, upper=_MAX)
        if col in FLAGS:
            out[col] = out[col].clip(upper=1)
        if col in RATIOS:
            out[col] = out[col].clip(upper=1)
    return out


def missing_columns(data) -> list:
    cols = set(data.columns) if isinstance(data, pd.DataFrame) else set()
    have = set(cols)
    if "protocol" in cols:
        have |= {"is_tcp", "is_udp", "is_icmp"}
    return [c for c in RAW_FEATURES if c not in have]


_IDX = {f: i for i, f in enumerate(RAW_FEATURES)}
_FLAG_IDX = [_IDX[f] for f in FLAGS | RATIOS]
_DEFAULT_ROW = np.array([DEFAULTS[f] for f in RAW_FEATURES], dtype=np.float64)
_PROTO_COL = {"is_tcp": "TCP", "is_udp": "UDP", "is_icmp": "ICMP"}


def _num(v, default):
    try:
        x = float(v)
    except (TypeError, ValueError):
        return default
    return x if math.isfinite(x) else default


def records_to_matrix(records) -> np.ndarray:
    """Fast path for list-of-dict input (single live events): pure NumPy/Python, no pandas overhead."""
    M = np.tile(_DEFAULT_ROW, (len(records), 1))
    for i, r in enumerate(records):
        proto = str(r.get("protocol") or "").upper()
        for f, j in _IDX.items():
            v = r.get(f)
            if v is None:
                if proto and f in _PROTO_COL:
                    M[i, j] = 1.0 if proto == _PROTO_COL[f] else 0.0
                continue
            M[i, j] = _num(v, _DEFAULT_ROW[j])
    np.clip(M, 0, _MAX, out=M)
    M[:, _FLAG_IDX] = np.minimum(M[:, _FLAG_IDX], 1.0)
    return M


def clean_record(rec: dict) -> dict:
    row = records_to_matrix([rec])[0]
    return {f: float(row[j]) for f, j in _IDX.items()}


def _finish(M: np.ndarray) -> np.ndarray:
    c = lambda name: M[:, _IDX[name]]  # noqa: E731
    tot_bytes = c("src_bytes") + c("dst_bytes")
    tot_pkts = np.maximum(c("src_pkts") + c("dst_pkts"), 1.0)
    dur = np.maximum(c("duration"), 1e-3)
    derived = np.column_stack([tot_bytes / dur, tot_pkts / dur, tot_bytes / tot_pkts, c("src_bytes") / (c("dst_bytes") + 1.0)])
    X = np.hstack([M, derived]).astype(np.float64)
    X[:, _LOG_IDX] = np.log1p(X[:, _LOG_IDX])
    return X


def engineer(data) -> np.ndarray:
    """Raw records -> model matrix (n, len(FEATURES)): derived features added, heavy tails log1p-compressed.

    DataFrames (uploads, training) take the vectorised pandas path; lists of dicts (live events) take a fast
    NumPy path. Both produce identical values (see tests)."""
    if isinstance(data, pd.DataFrame):
        M = to_frame(data)[RAW_FEATURES].to_numpy(dtype=np.float64)
    else:
        M = records_to_matrix(list(data))
    return _finish(M)
