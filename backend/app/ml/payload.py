"""Features extracted from request text (HTTP request targets, URLs, form fields).

Shared by training, the live pipeline and the signature detector so all three see identical values.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import unquote_plus

_SPECIAL = set("'\"<>;()\\|`$")

_SQL_PATTERNS = [re.compile(p, re.I) for p in (
    r"\bunion\b.{0,20}\bselect\b",
    r"\bselect\b.{1,60}\bfrom\b",
    r"\binsert\s+into\b",
    r"\bdrop\s+(table|database)\b",
    r"\bdelete\s+from\b",
    r"\bupdate\s+\w+\s+set\b",
    r"['\"]\s*or\s*['\"0-9]",
    r"\bor\s+1\s*=\s*1\b",
    r"\bsleep\s*\(\s*\d+",
    r"\bbenchmark\s*\(",
    r"information_schema",
    r"\bxp_cmdshell\b",
    r"(--|#)\s*$",
    r";\s*--",
    r"\border\s+by\s+\d+",
    r"'\s*\|\|\s*'",
    r"'\s*$",
)]

_XSS_PATTERNS = [re.compile(p, re.I) for p in (
    r"<\s*script",
    r"\bon(error|load|mouseover|focus|click)\s*=",
    r"javascript\s*:",
    r"<\s*iframe",
    r"<\s*svg[^>]*on\w+\s*=",
    r"document\.cookie",
    r"\balert\s*\(",
)]

_PHISH_WORDS = re.compile(r"(login|signin|verify|secure|account|update|confirm|password|banking|wallet)", re.I)
_IP_URL = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")


def decode_payload(text: str) -> str:
    """URL-decode up to twice (catches double-encoded evasion) and cap the length we inspect."""
    t = str(text)[:4096]
    for _ in range(2):
        d = unquote_plus(t)
        if d == t:
            break
        t = d
    return t


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def sql_hits(text: str) -> int:
    return sum(1 for p in _SQL_PATTERNS if p.search(text))


def xss_hits(text: str) -> int:
    return sum(1 for p in _XSS_PATTERNS if p.search(text))


def payload_features(text: str) -> dict:
    """Numeric features for one text payload (the raw text is never stored in the feature vector)."""
    raw = str(text or "")
    if not raw:
        return dict(payload_len=0.0, payload_entropy=0.0, special_char_ratio=0.0, sql_kw_count=0.0,
                    script_tag_count=0.0, has_ip_url=0.0, phish_kw_count=0.0)
    dec = decode_payload(raw)
    special = sum(1 for ch in dec if ch in _SPECIAL)
    return dict(
        payload_len=float(len(raw)),
        payload_entropy=float(shannon_entropy(dec)),
        special_char_ratio=special / max(len(dec), 1),
        sql_kw_count=float(sql_hits(dec)),
        script_tag_count=float(xss_hits(dec)),
        has_ip_url=1.0 if _IP_URL.search(dec) else 0.0,
        phish_kw_count=float(len(_PHISH_WORDS.findall(dec))),
    )
