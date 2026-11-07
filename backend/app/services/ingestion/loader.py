"""File ingestion: CSV upload parsing, column aliasing (CICIDS2017-style headers), NSL-KDD adapter and
sliding-window feature enrichment (source-IP frequency etc.)."""
from __future__ import annotations

import io
import re

import numpy as np
import pandas as pd

from app.ml.schema import RAW_FEATURES
from app.models.attacks import BENIGN

COLUMN_ALIASES = {
    "source_ip": "src_ip", "src": "src_ip", "source": "src_ip", "destination_ip": "dst_ip", "dest_ip": "dst_ip",
    "dst": "dst_ip", "destination": "dst_ip", "timestamp": "ts", "time": "ts", "destination_port": "dst_port",
    "dest_port": "dst_port", "dport": "dst_port", "port": "dst_port", "proto": "protocol",
    "payload": "payload_sample", "request": "payload_sample", "url": "payload_sample", "bytes_sent": "src_bytes",
    "bytes_received": "dst_bytes", "bytes": "src_bytes",
    # CICIDS2017 headers (after lower-casing/underscoring)
    "flow_duration": "duration_us", "total_fwd_packets": "src_pkts", "total_backward_packets": "dst_pkts",
    "total_length_of_fwd_packets": "src_bytes", "total_length_of_bwd_packets": "dst_bytes",
}
# Dataset label vocabularies -> platform classes. Coarse by necessity; unmapped labels are reported, not guessed.
LABEL_ALIASES = {
    "benign": BENIGN, "normal": BENIGN, "ddos": "DDoS", "portscan": "Port Scanning", "port scan": "Port Scanning",
    "ftp-patator": "Brute Force", "ssh-patator": "Brute Force", "bot": "Botnet", "botnet": "Botnet",
    "dos hulk": "DDoS", "dos goldeneye": "DDoS", "dos slowloris": "DDoS", "dos slowhttptest": "DDoS", "dos": "DDoS",
    "web attack - brute force": "Brute Force", "web attack - xss": "XSS", "web attack - sql injection": "SQL Injection",
    "brute force": "Brute Force", "sql injection": "SQL Injection", "xss": "XSS", "phishing": "Phishing",
    "malware": "Malware", "ransomware": "Ransomware", "insider threat": "Insider Threat", "mitm": "MITM",
    "zero-day": "Zero-Day", "infiltration": "Malware",
}
NSLKDD_ATTACKS = {
    "neptune": "DDoS", "smurf": "DDoS", "back": "DDoS", "teardrop": "DDoS", "pod": "DDoS", "land": "DDoS",
    "apache2": "DDoS", "udpstorm": "DDoS", "processtable": "DDoS", "mailbomb": "DDoS",
    "portsweep": "Port Scanning", "ipsweep": "Port Scanning", "nmap": "Port Scanning", "satan": "Port Scanning",
    "guess_passwd": "Brute Force", "buffer_overflow": "Malware", "rootkit": "Malware", "loadmodule": "Malware",
    "perl": "Malware", "sqlattack": "SQL Injection", "xss": "XSS", "normal": BENIGN,
}
NSLKDD_COLUMNS = (
    "duration protocol_type service flag src_bytes dst_bytes land wrong_fragment urgent hot num_failed_logins logged_in "
    "num_compromised root_shell su_attempted num_root num_file_creations num_shells num_access_files num_outbound_cmds "
    "is_host_login is_guest_login count srv_count serror_rate srv_serror_rate rerror_rate srv_rerror_rate same_srv_rate "
    "diff_srv_rate srv_diff_host_rate dst_host_count dst_host_srv_count dst_host_same_srv_rate dst_host_diff_srv_rate "
    "dst_host_same_src_port_rate dst_host_srv_diff_host_rate dst_host_serror_rate dst_host_srv_serror_rate "
    "dst_host_rerror_rate dst_host_srv_rerror_rate label difficulty").split()


class UploadError(ValueError):
    pass


def _norm(name: str) -> str:
    n = re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower()).strip("_")
    return COLUMN_ALIASES.get(n, n)


def map_label(value) -> str | None:
    return LABEL_ALIASES.get(str(value).strip().lower().replace("–", "-").replace("\ufffd", "-"))


def read_upload(data: bytes, max_rows: int) -> pd.DataFrame:
    if not data:
        raise UploadError("file is empty")
    try:
        df = pd.read_csv(io.BytesIO(data), nrows=max_rows + 1, encoding="utf-8", encoding_errors="replace",
                         on_bad_lines="skip", low_memory=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError, ValueError) as exc:
        raise UploadError(f"could not parse CSV: {exc}") from exc
    if len(df) > max_rows:
        raise UploadError(f"file has more than {max_rows} rows; split it or raise MAX_UPLOAD_ROWS")
    if df.empty:
        raise UploadError("file contains no data rows")
    df.columns = [_norm(c) for c in df.columns]
    df = df.loc[:, ~pd.Index(df.columns).duplicated()]
    if "duration_us" in df.columns and "duration" not in df.columns:
        df["duration"] = pd.to_numeric(df["duration_us"], errors="coerce") / 1e6
    if "protocol" in df.columns and "is_tcp" not in df.columns:
        pass  # handled in to_frame
    recognised = [c for c in df.columns if c in RAW_FEATURES or c in {"protocol", "payload_sample", "src_ip", "dst_ip"}]
    if len(recognised) < 3:
        raise UploadError("no recognisable columns; expected e.g. src_ip, dst_ip, protocol, src_bytes, dst_bytes, "
                          "duration, payload_sample (see data/schemas/feature_schema.json)")
    return df


def parse_timestamps(df: pd.DataFrame, fallback: float) -> np.ndarray:
    if "ts" not in df.columns:
        return np.full(len(df), fallback)
    s = pd.to_numeric(df["ts"], errors="coerce")
    if s.notna().mean() > 0.9:
        arr = s.to_numpy(dtype=float)
        arr = np.where(arr > 1e11, arr / 1000.0, arr)  # milliseconds -> seconds
    else:
        arr = pd.to_datetime(df["ts"], errors="coerce", utc=True).astype("int64").to_numpy(dtype=float) / 1e9
        arr = np.where(arr < 0, np.nan, arr)
    return np.where(np.isfinite(arr), arr, fallback)


def enrich_windows(df: pd.DataFrame, ts: np.ndarray, window: int = 60) -> pd.DataFrame:
    """Compute behavioural features per (source IP, time window) when the file lacks them:
    connection count, distinct destination ports and hosts."""
    if "src_ip" not in df.columns:
        return df
    key = pd.DataFrame({"src": df["src_ip"].astype(str), "win": (ts // window).astype("int64")})
    grp = key.groupby(["src", "win"])
    if "conn_count_src" not in df.columns:
        df["conn_count_src"] = grp["src"].transform("size").to_numpy()
    if "distinct_dst_ports" not in df.columns and "dst_port" in df.columns:
        key["p"] = df["dst_port"].to_numpy()
        df["distinct_dst_ports"] = key.groupby(["src", "win"])["p"].transform("nunique").to_numpy()
    if "distinct_dst_hosts" not in df.columns and "dst_ip" in df.columns:
        key["d"] = df["dst_ip"].astype(str).to_numpy()
        df["distinct_dst_hosts"] = key.groupby(["src", "win"])["d"].transform("nunique").to_numpy()
    return df


def load_nslkdd(path: str) -> pd.DataFrame:
    """Adapt an NSL-KDD file (KDDTrain+.txt, no header) to the platform schema.

    Mapping is approximate -- NSL-KDD has no payloads, TLS or timing fields, so many features stay at their
    defaults, and its attack families map onto only part of the platform's classes. Unmapped attack
    names are dropped (counted in the returned frame's `attrs['dropped']`)."""
    df = pd.read_csv(path, header=None, names=NSLKDD_COLUMNS, usecols=range(len(NSLKDD_COLUMNS)))
    out = pd.DataFrame({
        "duration": df["duration"], "protocol": df["protocol_type"], "src_bytes": df["src_bytes"],
        "dst_bytes": df["dst_bytes"], "conn_count_src": df["count"], "failed_logins": df["num_failed_logins"],
        "syn_ratio": df["serror_rate"], "error_rate": np.maximum(df["serror_rate"], df["rerror_rate"]),
        "distinct_dst_ports": np.round(df["diff_srv_rate"] * df["count"]),
    })
    out["src_pkts"] = np.maximum(1, np.round(df["src_bytes"] / 300))
    out["dst_pkts"] = np.round(df["dst_bytes"] / 300)
    out["label"] = df["label"].str.strip().str.lower().map(NSLKDD_ATTACKS)
    dropped = int(out["label"].isna().sum())
    out = out.dropna(subset=["label"]).reset_index(drop=True)
    out.attrs["dropped"] = dropped
    return out


def missing_columns_report(df: pd.DataFrame) -> list:
    """RAW features absent from the upload (they fall back to benign-looking defaults)."""
    have = set(df.columns)
    if "protocol" in have:
        have |= {"is_tcp", "is_udp", "is_icmp"}
    return [c for c in RAW_FEATURES if c not in have]
