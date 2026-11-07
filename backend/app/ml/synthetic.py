"""Synthetic network-flow generator (NSL-KDD / CICIDS-style features).

IMPORTANT: this is *simulated* data. It exists so the platform runs end-to-end without downloading
multi-GB public datasets. Metrics measured on it demonstrate that the pipeline works; they are NOT
a benchmark of real-world detection performance. Use `scripts/train_models.py --csv ...` with a
real, labelled capture (see docs/datasets) for that.

Realism devices (so results are not trivially perfect):
  * benign "hard negatives" (authorised scanners, forgotten passwords, nightly backups)
  * "stealth" attack variants that blend feature-wise with benign traffic
  * overlapping attack families (botnet vs DDoS vs malware, insider vs backup)
  * label noise
Zero-Day is a held-out *novel* family that is never part of the supervised training set.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from app.ml.payload import payload_features
from app.ml.schema import DEFAULTS, RAW_FEATURES
from app.models.attacks import BENIGN, CLASSES

PRIORS = {
    BENIGN: 0.62, "DDoS": 0.07, "SQL Injection": 0.035, "XSS": 0.03, "Phishing": 0.03, "Brute Force": 0.045,
    "Malware": 0.03, "Ransomware": 0.015, "Botnet": 0.035, "Port Scanning": 0.045, "Insider Threat": 0.02,
    "MITM": 0.025,
}
PAYLOAD_CLASSES = {BENIGN, "SQL Injection", "XSS", "Phishing"}  # classes whose payload is request text

_WORDS = ["wireless mouse", "usb c cable", "laptop stand", "monitor 27 inch", "keyboard", "headphones", "gadget pro",
          "black and white tv", "salt and pepper", "select your size", "update profile", "order status", "phone case"]
_PATHS = ["/", "/products", "/products/{n}", "/search?q={w}", "/cart", "/checkout", "/api/items?page={n}",
          "/account/orders", "/static/app.js", "/login", "/help/update-address", "/search?q={w}&sort=price"]
_BRANDS = ["examplebank", "paypa1-secure", "myshop-id", "cloudmail"]
_TLDS = ["xyz", "top", "info", "click", "com", "net"]


# ---------------------------------------------------------------- payload text builders
def _benign_payload(rng) -> str:
    p = str(rng.choice(_PATHS))
    return p.replace("{n}", str(rng.integers(1, 500))).replace("{w}", str(rng.choice(_WORDS)).replace(" ", "+"))


def _sqli_payload(rng, stealth: bool) -> str:
    n = int(rng.integers(1, 900))
    strong = ["/items?id={n}' OR '1'='1", "/search?q=' UNION SELECT username,password FROM users--",
              "/items?id={n}; DROP TABLE users;--", "/login?user=admin'--", "/items?id={n} AND SLEEP(5)",
              "/items?id=-1 UNION SELECT NULL,table_name FROM information_schema.tables--", "/items?id={n} OR 1=1"]
    mild = ["/items?id={n}'", "/items?id={n} order by 3--", "/search?q=laptop'||'x", "/items?id={n}%27"]
    t = str(rng.choice(mild if stealth else strong)).replace("{n}", str(n))
    if rng.random() < 0.3:
        t = t.replace(" ", "%20").replace("'", "%27")
    return t


def _xss_payload(rng, stealth: bool) -> str:
    strong = ["/search?q=<script>alert(1)</script>", "/comment?text=<img src=x onerror=alert(document.cookie)>",
              "/profile?name=\"><svg onload=alert(1)>", "/redirect?u=javascript:alert(1)", "/c?t=<iframe src=//x>"]
    mild = ["/search?q=<b onmouseover=x>", "/comment?text=<a href=javascript:void(0)>x</a>", "/p?n=\"onfocus=\"x"]
    t = str(rng.choice(mild if stealth else strong))
    if rng.random() < 0.25:
        t = t.replace("<", "%3C").replace(">", "%3E")
    return t


def _phish_payload(rng, stealth: bool) -> str:
    brand, tld = str(rng.choice(_BRANDS)), str(rng.choice(_TLDS))
    kw = str(rng.choice(["login", "verify", "secure-signin", "account-update", "confirm"]))
    variants = [f"https://{brand}-{kw}.{tld}/{kw}?id={rng.integers(1000, 99999)}",
                f"http://192.0.2.{rng.integers(2, 250)}/{kw}/account.php?s={rng.integers(1000, 99999)}",
                f"https://{kw}.{brand}.com.account-check.{tld}/update"]
    if stealth:
        variants = [f"https://{brand}.{tld}/portal?u={rng.integers(1, 999)}", f"https://{brand}.com/help"]
    return str(rng.choice(variants))


_PAYLOAD_BUILDERS = {"SQL Injection": _sqli_payload, "XSS": _xss_payload, "Phishing": _phish_payload}


def make_payload(cls: str, rng, stealth: bool = False) -> str:
    if cls == BENIGN:
        return _benign_payload(rng)
    return _PAYLOAD_BUILDERS[cls](rng, stealth)


# ---------------------------------------------------------------- numeric sampling helpers
def _ln(rng, mu, sigma, n):
    return rng.lognormal(mu, sigma, n)


def _bern(rng, p, n):
    return (rng.random(n) < p).astype(float)


def _base(n: int, rng) -> dict:
    """Start every sample from *background* feature draws shared by all classes.

    Anti-leakage: if non-overridden features were constants, a model could separate classes by "is this
    feature exactly the default?" -- an artefact of the generator, not a property of attacks.
    """
    d = {k: np.full(n, DEFAULTS[k], dtype=float) for k in RAW_FEATURES}
    d["off_hours"] = _bern(rng, 0.10, n)
    d["unusual_dest"] = _bern(rng, 0.04, n)
    d["cert_mismatch"] = _bern(rng, 0.01, n)
    d["latency_ratio"] = np.clip(rng.normal(1.0, 0.18, n), 0.5, 3)
    d["beacon_interval_std"] = np.clip(_ln(rng, 4.4, 1.0, n), 0, 5000)
    d["domain_age_days"] = np.clip(_ln(rng, 7.5, 1.0, n), 1, 20000)
    d["conn_count_src"] = np.maximum(1, np.round(_ln(rng, 1.2, 0.7, n)))
    d["error_rate"] = rng.beta(1.2, 40, n)
    d["syn_ratio"] = rng.beta(2, 12, n)
    d["dns_query_rate"] = _ln(rng, 0.5, 0.6, n)
    return d


def _proto(d, rng, n, probs):
    pick = rng.choice(3, n, p=probs)
    d["is_tcp"], d["is_udp"], d["is_icmp"] = (pick == 0).astype(float), (pick == 1).astype(float), (pick == 2).astype(float)


def _pkts(d, rng, n, avg_lo, avg_hi):
    avg = rng.uniform(avg_lo, avg_hi, n)
    d["src_pkts"] = np.maximum(1, np.round(d["src_bytes"] / avg))
    d["dst_pkts"] = np.maximum(0, np.round(d["dst_bytes"] / avg))


def _apply_text_payload(d, rng, cls, n, stealth_mask):
    keys = ["payload_len", "payload_entropy", "special_char_ratio", "sql_kw_count", "script_tag_count",
            "has_ip_url", "phish_kw_count"]
    rows = [payload_features(make_payload(cls, rng, bool(stealth_mask[i]))) for i in range(n)]
    for k in keys:
        d[k] = np.array([r[k] for r in rows], dtype=float)


# ---------------------------------------------------------------- per-class samplers
def _benign(rng, n):
    kinds = rng.choice(6, n, p=[0.45, 0.15, 0.10, 0.10, 0.05, 0.15])
    parts = []
    for k in range(6):
        m = int((kinds == k).sum())
        if m == 0:
            continue
        d = _base(m, rng)
        if k == 0:    # web browsing
            d["dst_port"] = rng.choice([443, 80, 8080], m, p=[0.7, 0.25, 0.05]).astype(float)
            d["duration"] = _ln(rng, -0.7, 1.0, m)
            d["src_bytes"], d["dst_bytes"] = _ln(rng, 6.5, 0.9, m), _ln(rng, 8.5, 1.3, m)
            _pkts(d, rng, m, 300, 900)
            _apply_text_payload(d, rng, BENIGN, m, np.zeros(m))
        elif k == 1:  # dns
            _proto(d, rng, m, [0, 1, 0]); d["is_udp"][:] = 1; d["is_tcp"][:] = 0
            d["dst_port"][:] = 53; d["duration"] = _ln(rng, -3, 0.6, m)
            d["src_bytes"], d["dst_bytes"] = _ln(rng, 4.3, 0.3, m), _ln(rng, 5.0, 0.4, m)
            _pkts(d, rng, m, 70, 150); d["dns_query_rate"] = _ln(rng, 1.5, 0.7, m)
            d["payload_len"] = _ln(rng, 3.5, 0.4, m); d["payload_entropy"] = np.clip(rng.normal(3.5, 0.6, m), 0, 8)
        elif k == 2:  # ssh / rdp admin sessions
            d["dst_port"] = rng.choice([22, 3389], m).astype(float); d["duration"] = _ln(rng, 5, 1.0, m)
            d["src_bytes"], d["dst_bytes"] = _ln(rng, 8.5, 1.0, m), _ln(rng, 9.0, 1.0, m)
            _pkts(d, rng, m, 100, 400); d["failed_logins"] = rng.poisson(0.15, m).astype(float)
            d["payload_entropy"] = np.clip(rng.normal(7.2, 0.4, m), 0, 8); d["payload_len"] = _ln(rng, 5, 0.8, m)
        elif k == 3:  # bulk transfer / nightly backup (hard negative for insider & ransomware)
            d["dst_port"] = rng.choice([443, 445, 21, 22], m).astype(float); d["duration"] = _ln(rng, 4, 0.9, m)
            d["src_bytes"], d["dst_bytes"] = _ln(rng, 15, 1.2, m), _ln(rng, 8, 1.0, m)
            _pkts(d, rng, m, 800, 1400); d["off_hours"] = _bern(rng, 0.35, m); d["unusual_dest"] = _bern(rng, 0.04, m)
            d["smb_write_rate"] = np.where(d["dst_port"] == 445, _ln(rng, 2.5, 1.0, m), 0.0)
            d["payload_entropy"] = np.clip(rng.normal(7.3, 0.4, m), 0, 8); d["payload_len"] = _ln(rng, 7, 0.8, m)
            d["distinct_dst_hosts"] = np.maximum(1, rng.poisson(1.0, m)).astype(float)
        elif k == 4:  # icmp ping
            _proto(d, rng, m, [0, 0, 1]); d["is_icmp"][:] = 1; d["is_tcp"][:] = 0; d["is_udp"][:] = 0
            d["dst_port"][:] = 0; d["duration"] = _ln(rng, -2, 0.5, m)
            d["src_bytes"], d["dst_bytes"] = _ln(rng, 4.4, 0.2, m), _ln(rng, 4.4, 0.2, m)
            _pkts(d, rng, m, 60, 100)
        else:         # misc internal services
            d["dst_port"] = rng.integers(1024, 65535, m).astype(float); d["duration"] = _ln(rng, 0.5, 1.0, m)
            d["src_bytes"], d["dst_bytes"] = _ln(rng, 7.0, 1.2, m), _ln(rng, 7.5, 1.3, m)
            _pkts(d, rng, m, 200, 900); d["payload_len"] = _ln(rng, 4.5, 1.0, m)
            d["payload_entropy"] = np.clip(rng.normal(5.5, 1.3, m), 0, 8)
        # hard negatives: authorised scanner, mistyped passwords, bursty crawler
        hn = rng.random(m)
        scan = hn < 0.015
        d["distinct_dst_ports"][scan] = rng.integers(8, 40, scan.sum()); d["syn_ratio"][scan] = rng.uniform(0.5, 0.9, scan.sum())
        pw = (hn >= 0.015) & (hn < 0.035)
        d["failed_logins"][pw] = rng.integers(2, 6, pw.sum())
        burst = (hn >= 0.035) & (hn < 0.05)
        d["conn_count_src"][burst] = rng.integers(30, 120, burst.sum())
        parts.append(pd.DataFrame(d))
    return pd.concat(parts, ignore_index=True)


def _ddos(rng, n):
    d = _base(n, rng)
    _proto(d, rng, n, [0.55, 0.25, 0.20])
    dist = rng.random(n) < 0.5  # distributed slice (low per-source volume) vs single-source flood
    d["dst_port"] = rng.choice([80, 443, 53, 0], n).astype(float)
    d["duration"] = np.clip(_ln(rng, 0.3, 0.9, n), 0.01, 60)
    d["src_bytes"] = np.where(dist, _ln(rng, 8.0, 0.8, n), _ln(rng, 11.5, 1.0, n))
    d["dst_bytes"] = _ln(rng, 3.0, 1.2, n) * rng.random(n)
    _pkts(d, rng, n, 40, 150)
    d["conn_count_src"] = np.where(dist, rng.integers(15, 150, n), rng.integers(300, 4000, n)).astype(float)
    d["syn_ratio"] = rng.beta(8, 1.5, n); d["error_rate"] = rng.beta(4, 3, n)
    d["payload_len"] = rng.uniform(0, 80, n); d["payload_entropy"] = np.clip(rng.normal(3.0, 1.2, n), 0, 8)
    d["distinct_dst_hosts"] = np.ones(n)
    return pd.DataFrame(d)


def _brute(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.choice([22, 3389, 21, 445, 443, 80], n, p=[0.35, 0.2, 0.1, 0.1, 0.15, 0.1]).astype(float)
    d["duration"] = _ln(rng, -1.2, 0.8, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 6.0, 0.6, n), _ln(rng, 6.0, 0.6, n)
    _pkts(d, rng, n, 80, 250)
    d["failed_logins"] = np.round(_ln(rng, 3.0, 0.9, n)).clip(3, 400)
    d["conn_count_src"] = np.round(_ln(rng, 3.8, 0.9, n)).clip(5, 800)
    d["error_rate"] = rng.beta(3, 4, n); d["syn_ratio"] = rng.beta(3, 5, n)
    d["payload_entropy"] = np.clip(rng.normal(5.0, 1.0, n), 0, 8); d["payload_len"] = _ln(rng, 4.2, 0.5, n)
    d["off_hours"] = _bern(rng, 0.4, n)
    return pd.DataFrame(d)


def _malware(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.choice([443, 8080, 4444, 80, 8443], n).astype(float)
    d["duration"] = _ln(rng, 1.5, 1.0, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 6.5, 0.9, n), _ln(rng, 11.5, 1.1, n)
    _pkts(d, rng, n, 300, 1200)
    d["payload_entropy"] = np.clip(rng.normal(7.3, 0.5, n), 3, 8); d["payload_len"] = _ln(rng, 8, 1.0, n)
    d["unusual_dest"] = _bern(rng, 0.7, n); d["off_hours"] = _bern(rng, 0.5, n)
    d["beacon_interval_std"] = np.clip(_ln(rng, 2.5, 1.0, n), 0, 3000)
    d["dns_query_rate"] = _ln(rng, 1.6, 0.8, n); d["domain_age_days"] = np.clip(_ln(rng, 4.5, 1.2, n), 1, 20000)
    d["error_rate"] = rng.beta(1.5, 20, n)
    return pd.DataFrame(d)


def _ransom(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.choice([445, 139, 443], n, p=[0.75, 0.1, 0.15]).astype(float)
    d["duration"] = _ln(rng, 3.2, 0.9, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 14, 1.0, n), _ln(rng, 8.0, 1.0, n)
    _pkts(d, rng, n, 600, 1400)
    d["smb_write_rate"] = _ln(rng, 5.0, 0.9, n); d["payload_entropy"] = np.clip(rng.normal(7.8, 0.15, n), 5, 8)
    d["payload_len"] = _ln(rng, 8.0, 0.8, n); d["distinct_dst_hosts"] = np.maximum(1, np.round(_ln(rng, 1.8, 0.9, n)))
    d["off_hours"] = _bern(rng, 0.5, n); d["error_rate"] = rng.beta(1.5, 15, n)
    return pd.DataFrame(d)


def _botnet(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.choice([6667, 8080, 443, 53, 8443], n).astype(float)
    d["duration"] = _ln(rng, -1.0, 0.8, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 5.0, 0.7, n), _ln(rng, 5.3, 0.8, n)
    _pkts(d, rng, n, 60, 250)
    d["beacon_interval_std"] = np.clip(_ln(rng, -0.2, 0.9, n), 0, 100); d["dns_query_rate"] = _ln(rng, 3.3, 0.8, n)
    d["unusual_dest"] = _bern(rng, 0.85, n); d["distinct_dst_hosts"] = np.maximum(1, rng.poisson(1.2, n)).astype(float)
    d["conn_count_src"] = np.maximum(1, np.round(_ln(rng, 2.0, 0.9, n)))
    d["payload_entropy"] = np.clip(rng.normal(5.2, 1.3, n), 0, 8); d["payload_len"] = _ln(rng, 4.5, 0.7, n)
    d["domain_age_days"] = np.clip(_ln(rng, 4.8, 1.3, n), 1, 20000); d["off_hours"] = _bern(rng, 0.35, n)
    return pd.DataFrame(d)


def _portscan(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.integers(1, 65535, n).astype(float); d["duration"] = _ln(rng, -4.0, 0.9, n)
    d["src_bytes"], d["dst_bytes"] = rng.uniform(40, 130, n), rng.uniform(0, 110, n) * _bern(rng, 0.4, n)
    _pkts(d, rng, n, 40, 80)
    d["distinct_dst_ports"] = np.round(_ln(rng, 4.2, 1.0, n)).clip(6, 2000)
    d["distinct_dst_hosts"] = np.maximum(1, np.round(_ln(rng, 0.7, 0.9, n)))
    d["conn_count_src"] = np.round(_ln(rng, 3.8, 1.0, n)).clip(8, 3000)
    d["syn_ratio"] = rng.beta(10, 1.3, n); d["error_rate"] = rng.beta(7, 2.5, n)
    d["payload_len"] = np.zeros(n); d["off_hours"] = _bern(rng, 0.3, n)
    return pd.DataFrame(d)


def _insider(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.choice([443, 22, 21, 80], n, p=[0.55, 0.2, 0.15, 0.1]).astype(float)
    d["duration"] = _ln(rng, 4.2, 0.9, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 16.5, 1.2, n), _ln(rng, 7.5, 1.0, n)
    _pkts(d, rng, n, 900, 1450)
    d["off_hours"] = _bern(rng, 0.8, n); d["unusual_dest"] = _bern(rng, 0.8, n)
    d["failed_logins"] = rng.poisson(0.6, n).astype(float); d["domain_age_days"] = np.clip(_ln(rng, 6.0, 1.5, n), 1, 20000)
    d["payload_entropy"] = np.clip(rng.normal(7.4, 0.35, n), 0, 8); d["payload_len"] = _ln(rng, 8.0, 0.8, n)
    d["conn_count_src"] = np.maximum(1, np.round(_ln(rng, 1.0, 0.7, n)))
    return pd.DataFrame(d)


def _mitm(rng, n):
    d = _base(n, rng)
    d["dst_port"] = rng.choice([443, 80, 993, 8443], n).astype(float); d["duration"] = _ln(rng, 0.3, 0.9, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 7.0, 1.0, n), _ln(rng, 8.8, 1.2, n)
    _pkts(d, rng, n, 300, 900)
    d["cert_mismatch"] = _bern(rng, 0.7, n); d["latency_ratio"] = np.clip(rng.normal(1.9, 0.6, n), 0.7, 6)
    d["error_rate"] = rng.beta(1.5, 14, n); d["payload_entropy"] = np.clip(rng.normal(6.8, 0.7, n), 0, 8)
    d["payload_len"] = _ln(rng, 5.5, 0.8, n); d["unusual_dest"] = _bern(rng, 0.15, n)
    return pd.DataFrame(d)


def _novel(rng, n):
    """Held-out 'Zero-Day' family: covert tunnel / unseen exploit chain. NEVER used for training."""
    d = _base(n, rng)
    d["dst_port"] = rng.choice([53, 443, 8443, 4444, 31337], n).astype(float)
    d["duration"] = _ln(rng, 3.5, 0.6, n)
    d["src_bytes"], d["dst_bytes"] = _ln(rng, 10.5, 0.8, n), _ln(rng, 10.0, 0.8, n)
    _pkts(d, rng, n, 120, 600)
    d["payload_entropy"] = np.clip(rng.normal(7.6, 0.2, n), 5, 8); d["payload_len"] = _ln(rng, 6.5, 0.6, n)
    d["dns_query_rate"] = _ln(rng, 5.0, 0.5, n); d["beacon_interval_std"] = np.clip(_ln(rng, 0.5, 0.6, n), 0, 50)
    d["conn_count_src"] = np.maximum(1, np.round(_ln(rng, 2.5, 0.5, n))); d["unusual_dest"] = _bern(rng, 0.9, n)
    d["latency_ratio"] = np.clip(rng.normal(1.3, 0.3, n), 0.5, 4); d["off_hours"] = _bern(rng, 0.6, n)
    d["cert_mismatch"] = _bern(rng, 0.3, n); d["error_rate"] = rng.beta(1.5, 20, n)
    return pd.DataFrame(d)


def _text_class(cls):
    def sampler(rng, n):
        d = _base(n, rng)
        stealth = rng.random(n) < 0.0  # stealth handled by caller; payload built non-stealth here
        d["dst_port"] = rng.choice([443, 80, 8080], n, p=[0.6, 0.3, 0.1]).astype(float)
        d["duration"] = _ln(rng, -0.5, 0.9, n)
        d["src_bytes"], d["dst_bytes"] = _ln(rng, 6.8, 0.8, n), _ln(rng, 8.0, 1.3, n)
        _pkts(d, rng, n, 300, 900)
        d["conn_count_src"] = np.maximum(1, np.round(_ln(rng, 1.8, 0.8, n)))
        d["off_hours"] = _bern(rng, 0.25, n)
        if cls == "Phishing":
            d["domain_age_days"] = np.clip(_ln(rng, 2.8, 1.2, n), 0, 20000)
            d["cert_mismatch"] = _bern(rng, 0.25, n); d["unusual_dest"] = _bern(rng, 0.5, n)
        _apply_text_payload(d, rng, cls, n, stealth)
        return pd.DataFrame(d)
    return sampler


SAMPLERS = {BENIGN: _benign, "DDoS": _ddos, "Brute Force": _brute, "Malware": _malware, "Ransomware": _ransom,
            "Botnet": _botnet, "Port Scanning": _portscan, "Insider Threat": _insider, "MITM": _mitm,
            "SQL Injection": _text_class("SQL Injection"), "XSS": _text_class("XSS"), "Phishing": _text_class("Phishing"),
            "Zero-Day": _novel}


def sample_class(cls: str, n: int, rng, stealth: float = 0.2) -> pd.DataFrame:
    """Sample `n` rows of one class. A `stealth` fraction of attack rows is blended feature-wise with benign rows."""
    if n <= 0:
        return pd.DataFrame(columns=RAW_FEATURES)
    df = SAMPLERS[cls](rng, n)
    if cls == BENIGN or stealth <= 0:
        return df[RAW_FEATURES]
    mask = rng.random(n) < stealth
    m = int(mask.sum())
    if m:
        benign = _benign(rng, m).sample(frac=1.0, random_state=int(rng.integers(0, 2**31 - 1))).reset_index(drop=True)
        mix = rng.uniform(0.35, 0.7, (m, 1))
        take_benign = rng.random((m, len(RAW_FEATURES))) < mix
        idx = np.flatnonzero(mask)
        cur = df.loc[idx, RAW_FEATURES].to_numpy(dtype=float)
        ben = benign[RAW_FEATURES].to_numpy(dtype=float)
        df.loc[idx, RAW_FEATURES] = np.where(take_benign, ben, cur)
    return df[RAW_FEATURES]


def generate_dataset(n: int = 15000, seed: int = 42, stealth: float = 0.2, label_noise: float = 0.005,
                     priors: dict | None = None, novel_n: int = 0) -> pd.DataFrame:
    """Labelled dataset: RAW_FEATURES + `label`. `novel_n` extra Zero-Day rows can be appended (evaluation only)."""
    rng = np.random.default_rng(seed)
    priors = priors or PRIORS
    names = list(priors)
    p = np.array([priors[k] for k in names], dtype=float)
    counts = rng.multinomial(n, p / p.sum())
    frames = []
    for cls, c in zip(names, counts):
        f = sample_class(cls, int(c), rng, stealth)
        f["label"] = cls
        frames.append(f)
    if novel_n:
        f = sample_class("Zero-Day", novel_n, rng, 0.0)
        f["label"] = "Zero-Day"
        frames.append(f)
    df = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    if label_noise > 0:
        flip = (rng.random(len(df)) < label_noise) & (df["label"] != "Zero-Day")
        df.loc[flip, "label"] = rng.choice(CLASSES, int(flip.sum()))
    return df


# ---------------------------------------------------------------- single events for the simulator / lab
_ATTACKER_NETS = ["198.51.100", "203.0.113", "192.0.2"]  # RFC 5737 documentation ranges: never real hosts


def generate_event(cls: str, rng, stealth: float = 0.0, attacker_ip: str | None = None) -> dict:
    """One flow event (features + addressing + optional payload text) for the live simulator and attack lab."""
    row = sample_class(cls, 1, rng, stealth if cls != BENIGN else 0.0).iloc[0].to_dict()
    ev = {k: float(v) for k, v in row.items()}
    payload = ""
    # Attach request text only where it is coherent: always for text-borne attacks, and for benign flows only when
    # the sampled flow is web-like (TCP to an HTTP port with text-like entropy). Otherwise a DNS lookup or a 3 MB backup
    # would carry a 25-character web request -- an incoherent flow that anomaly detection (rightly) rejects.
    web_like = ev["is_tcp"] == 1 and ev["dst_port"] in (80, 443, 8080) and ev["payload_entropy"] < 5.2
    if cls != BENIGN and cls in PAYLOAD_CLASSES or (cls == BENIGN and web_like):
        payload = make_payload(cls, rng, stealth > 0 and rng.random() < stealth)
        ev.update(payload_features(payload))
    if cls == BENIGN:
        src = f"192.168.1.{int(rng.integers(2, 250))}"
    else:
        src = attacker_ip or f"{rng.choice(_ATTACKER_NETS)}.{int(rng.integers(2, 250))}"
    ev["src_ip"] = src
    ev["dst_ip"] = f"10.0.0.{int(rng.choice([10, 20, 30, 40, 50, int(rng.integers(2, 250))]))}"
    ev["protocol"] = "TCP" if ev["is_tcp"] else ("UDP" if ev["is_udp"] else "ICMP")
    ev["payload_sample"] = payload
    return ev
