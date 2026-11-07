"""Signature (rule-based) detector -- the 'known bad patterns' half of the hybrid approach.

Rules are deliberately conservative (high precision): a hit is strong evidence on its own. Anything
subtler is left to the ML ensemble. Payload text is URL-decoded (twice) before matching so simple
encoding evasion does not hide an attack.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.ml.payload import _SQL_PATTERNS, decode_payload, sql_hits, xss_hits

AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 3389, 5900}
_SQL_STRONG = [re.compile(p, re.I) for p in (
    r"\bunion\b.{0,20}\bselect\b", r"\bor\s+1\s*=\s*1\b", r"['\"]\s*or\s*['\"]\s*\d*\s*['\"]?\s*=\s*['\"]?\d*",
    r"\bsleep\s*\(\s*\d+", r"\bbenchmark\s*\(", r"information_schema", r"\bdrop\s+(table|database)\b", r"\bxp_cmdshell\b")]
_XSS_STRONG = [re.compile(p, re.I) for p in (r"<\s*script", r"\bon(error|load)\s*=", r"javascript\s*:", r"<\s*iframe")]
_IP_URL = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")


@dataclass
class SignatureHit:
    attack_type: str
    rule_id: str
    confidence: float
    description: str


def _f(ev: dict, key: str, default: float = 0.0) -> float:
    try:
        return float(ev.get(key, default))
    except (TypeError, ValueError):
        return default


class SignatureEngine:
    def scan(self, ev: dict) -> list:
        """`ev` holds raw features plus optional `payload_sample` text."""
        hits = []
        text = decode_payload(ev.get("payload_sample") or "")
        if text:
            if any(p.search(text) for p in _SQL_STRONG):
                hits.append(SignatureHit("SQL Injection", "SIG-SQLI-001", 0.96, "Classic SQL injection construct in request"))
            elif sql_hits(text) >= 2:
                hits.append(SignatureHit("SQL Injection", "SIG-SQLI-002", 0.88, "Multiple SQL keywords/operators in request"))
            if any(p.search(text) for p in _XSS_STRONG):
                hits.append(SignatureHit("XSS", "SIG-XSS-001", 0.96, "Script/event-handler injection in request"))
            elif xss_hits(text) >= 2:
                hits.append(SignatureHit("XSS", "SIG-XSS-002", 0.85, "Multiple scripting indicators in request"))
            if text.lower().startswith("http") and _IP_URL.search(text) and _f(ev, "phish_kw_count") >= 1:
                hits.append(SignatureHit("Phishing", "SIG-PHISH-001", 0.82, "Credential-themed URL pointing at a raw IP"))
        if _f(ev, "phish_kw_count") >= 2 and _f(ev, "domain_age_days", 3000) < 30 and _f(ev, "payload_len") > 0:
            hits.append(SignatureHit("Phishing", "SIG-PHISH-002", 0.84, "Credential-themed URL on a domain younger than 30 days"))
        failed, port = _f(ev, "failed_logins"), int(_f(ev, "dst_port"))
        if failed >= 15 or (failed >= 8 and port in AUTH_PORTS):
            hits.append(SignatureHit("Brute Force", "SIG-BF-001", 0.93 if failed >= 15 else 0.88,
                                     f"{int(failed)} failed logins from one source"))
        if _f(ev, "distinct_dst_ports") >= 25 and _f(ev, "error_rate") >= 0.5:
            hits.append(SignatureHit("Port Scanning", "SIG-SCAN-001", 0.9, "Many distinct ports probed with a high error rate"))
        pps = (_f(ev, "src_pkts") + _f(ev, "dst_pkts")) / max(_f(ev, "duration", 1.0), 1e-3)
        if pps >= 3000 and _f(ev, "conn_count_src") >= 200:
            hits.append(SignatureHit("DDoS", "SIG-DDOS-001", 0.9, "Packet and connection rate far above flood threshold"))
        if _f(ev, "smb_write_rate") >= 150 and _f(ev, "payload_entropy") >= 7.6:
            hits.append(SignatureHit("Ransomware", "SIG-RANSOM-001", 0.9, "Bulk SMB writes of near-random (encrypted) data"))
        return hits
