"""The common web-event format and its validation.

Every web-server connector, whatever the original log format (Nginx, Apache, JSON...), reduces a log line to:

    {"eid": "...", "ts": 1700000000.5, "src_ip": "203.0.113.9", "method": "GET", "path": "/search",
     "query": "q=shoes", "status": 200, "bytes": 5120, "ua": "Mozilla/5.0 ...", "host": "shop.example.com"}

The server never trusts the collector: everything is re-validated and bounded here, and the source's privacy
policy (excluded paths, redacted parameters) is enforced again as a safety net.
"""
from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime, timezone

METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PROPFIND"}
MAX_PATH, MAX_QUERY, MAX_UA, MAX_HOST = 2048, 4096, 300, 253
REDACTED = "[REDACTED]"
DEFAULT_REDACT_PARAMS = ["password", "passwd", "pass", "pwd", "token", "user_token", "csrf_token", "_token", "authenticity_token", "access_token", "refresh_token",
                         "jwt", "auth", "secret", "api_key", "apikey", "authorization", "session", "sessionid", "csrf"]

DEFAULT_POLICY = dict(
    exclude_paths=[],                       # URL path prefixes that are never analysed or stored (e.g. /health)
    redact_params=DEFAULT_REDACT_PARAMS,    # query-parameter names whose values are replaced before storage
    pseudonymize_ips=False,                 # collector replaces real IPs with stable pseudonyms (100.64.0.0/10)
    protected_ip="",                        # address of the protected server, shown as the attack target
)


def normalize_policy(policy: dict | None) -> dict:
    """Validate/clean a policy dict coming from the admin UI or API."""
    p = dict(DEFAULT_POLICY)
    policy = policy or {}
    ex = [str(x).strip()[:200] for x in (policy.get("exclude_paths") or []) if str(x).strip()]
    p["exclude_paths"] = [x if x.startswith("/") else "/" + x for x in ex][:50]
    rp = [re.sub(r"[^A-Za-z0-9_.-]", "", str(x).lower())[:64] for x in (policy.get("redact_params") or DEFAULT_REDACT_PARAMS)]
    p["redact_params"] = sorted({x for x in rp if x})[:100]
    p["pseudonymize_ips"] = bool(policy.get("pseudonymize_ips", False))
    pip = str(policy.get("protected_ip") or "").strip()
    try:
        p["protected_ip"] = str(ipaddress.ip_address(pip)) if pip else ""
    except ValueError:
        p["protected_ip"] = ""
    return p


def is_pseudonymised(ip: str) -> bool:
    """Pseudonymised sources live in 100.64.0.0/10 (carrier-grade NAT space, never a real public address)."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


def redact_query(query: str, names) -> str:
    """Replace the value of every listed parameter (case-insensitive) with [REDACTED]."""
    if not query or not names:
        return query
    names = {n.lower() for n in names}
    out = []
    for part in query.split("&"):
        key, sep, _val = part.partition("=")
        out.append(f"{key}={REDACTED}" if sep and key.lower() in names else part)
    return "&".join(out)


def _ts(value) -> float:
    now = time.time()
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value.strip())):
            t = float(value)
            t = t / 1000.0 if t > 1e11 else t
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            t = (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except (TypeError, ValueError, OverflowError):
        return now
    return now if (t > now + 300 or t < 0) else t  # future / nonsense timestamps are replaced with "now"


def _s(value, limit) -> str:
    return "".join(ch for ch in str(value if value is not None else "")[:limit] if ch >= " " and ch != "\x7f")


def normalize_web_event(raw, policy: dict):
    """Return (event, None) on success, (None, reason) when dropped. reason: 'invalid' | 'excluded'."""
    if not isinstance(raw, dict):
        return None, "invalid"
    try:
        ip = str(ipaddress.ip_address(str(raw.get("src_ip", "")).strip()))
    except ValueError:
        return None, "invalid"
    method = str(raw.get("method") or "GET").upper()[:10]
    if method not in METHODS:
        method = "OTHER"
    path = _s(raw.get("path") or "/", MAX_PATH) or "/"
    if not path.startswith("/"):
        path = "/" + path
    if any(path.startswith(x) for x in policy.get("exclude_paths", [])):
        return None, "excluded"
    query = redact_query(_s(raw.get("query"), MAX_QUERY), policy.get("redact_params", []))
    try:
        status = int(raw.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        size = max(0, int(raw.get("bytes") or 0))
    except (TypeError, ValueError):
        size = 0
    request_line = f"{method} {path}" + (f"?{query}" if query else "")
    return dict(
        eid=_s(raw.get("eid"), 64) or None, ts=_ts(raw.get("ts")), src_ip=ip, method=method, path=path, query=query,
        status=status if 100 <= status <= 599 else 0, bytes=min(size, 10**12), ua=_s(raw.get("ua"), MAX_UA),
        host=_s(raw.get("host"), MAX_HOST), request_line=request_line[:600],
    ), None


def target_text(ev: dict) -> str:
    """The text the detectors inspect: path + query, exactly as an attacker would have typed it."""
    return ev["path"] + (("?" + ev["query"]) if ev["query"] else "")


def to_record(ev: dict, source_id: int, protected_ip: str = "") -> dict:
    """Shape a web event like the generic event dict the repository stores (so alerts/events share one table)."""
    return dict(
        ts=ev["ts"], src_ip=ev["src_ip"], dst_ip=protected_ip or "0.0.0.0", protocol="HTTP",
        payload_sample=ev["request_line"][:500], source_id=source_id, eid=ev.get("eid"),
        features=dict(dst_port=0, src_bytes=0, dst_bytes=ev["bytes"], status=ev["status"], method=ev["method"],
                      host=ev["host"], ua=ev["ua"][:200], path=ev["path"][:300]),
    )
