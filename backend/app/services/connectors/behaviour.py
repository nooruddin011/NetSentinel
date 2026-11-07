"""Behaviour tracker: attacks that are visible only over *time* (floods, password guessing, directory scans).

A single request to /login is normal; forty in a minute from one address is not. State is a small sliding window
per (source, client IP), measured in *event time* (so replaying an old log behaves the same as live traffic) and
bounded in memory (least-recently-seen clients are dropped).
"""
from __future__ import annotations

import re
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass

from app.detectors.webrules import WebHit

_LOGIN_PATH = re.compile(r"(?i)/(login|log-in|signin|sign-in|signon|auth|authenticate|session|sessions|token|oauth|wp-login\.php|xmlrpc\.php|password)\b")
_LOGIN_QS = re.compile(r"(?i)(^|&)(password|passwd|pwd|pass)=")
_STATIC = re.compile(r"(?i)\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)$")


@dataclass
class BehaviourConfig:
    flood_requests: int = 120      # requests from one client within flood_window seconds
    flood_window: float = 10.0
    brute_attempts: int = 8        # login-like requests within brute_window seconds
    brute_window: float = 60.0
    brute_failures: int = 5        # 401/403 answers on login-like paths within brute_window
    recon_errors: int = 15         # 404/403 answers within recon_window seconds ...
    recon_distinct_paths: int = 10  # ... on at least this many different paths
    recon_window: float = 60.0
    max_clients: int = 20000


def is_login_like(ev: dict) -> bool:
    return bool(_LOGIN_PATH.search(ev["path"]) or _LOGIN_QS.search(ev["query"] or ""))


class _Client:
    __slots__ = ("reqs", "login", "fails", "errors")

    def __init__(self):
        self.reqs = deque()     # timestamps of every counted request
        self.login = deque()    # timestamps of login-like requests
        self.fails = deque()    # timestamps of 401/403 on login-like requests
        self.errors = deque()   # (timestamp, path) of 404/403 answers


def _trim(dq, cutoff, key=lambda x: x):
    while dq and key(dq[0]) < cutoff:
        dq.popleft()


class BehaviourTracker:
    def __init__(self, config: BehaviourConfig | None = None):
        self.cfg = config or BehaviourConfig()
        self._clients: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def reset(self):
        with self._lock:
            self._clients.clear()

    def observe(self, source_id, ev: dict) -> list:
        """Feed one event (in time order). Returns behaviour hits triggered by it (possibly none)."""
        cfg, t = self.cfg, ev["ts"]
        key = (source_id, ev["src_ip"])
        hits = []
        with self._lock:
            c = self._clients.get(key)
            if c is None:
                c = self._clients[key] = _Client()
                if len(self._clients) > cfg.max_clients:
                    self._clients.popitem(last=False)
            else:
                self._clients.move_to_end(key)
            static = bool(_STATIC.search(ev["path"]))
            if not static:  # page assets do not count towards "requests per second" (a browser loads dozens)
                c.reqs.append(t)
            login = is_login_like(ev)
            if login:
                c.login.append(t)
                if ev["status"] in (401, 403):
                    c.fails.append(t)
            if ev["status"] in (404, 403) and not static:
                c.errors.append((t, ev["path"]))
            _trim(c.reqs, t - cfg.flood_window)
            _trim(c.login, t - cfg.brute_window)
            _trim(c.fails, t - cfg.brute_window)
            _trim(c.errors, t - cfg.recon_window, key=lambda x: x[0])

            # A verdict is attached only to events that CONTRIBUTE to the pattern. Otherwise, one address doing several things in a
            # short time would have every later request inherit the earlier verdict (a scan labelled "brute force", for instance).
            if not static and len(c.reqs) >= cfg.flood_requests:
                n = len(c.reqs)
                hits.append(WebHit("DDoS", "WEB-BEH-FLOOD", min(0.97, 0.80 + 0.17 * min(1.0, (n - cfg.flood_requests) / cfg.flood_requests)),
                                   f"{n} requests from one client in {cfg.flood_window:.0f}s (HTTP flood)", f"{n} req/{cfg.flood_window:.0f}s", "behaviour"))
            if login and (len(c.login) >= cfg.brute_attempts or len(c.fails) >= cfg.brute_failures):
                n = max(len(c.login), len(c.fails))
                hits.append(WebHit("Brute Force", "WEB-BEH-BRUTE", min(0.97, 0.78 + 0.19 * min(1.0, n / (4 * cfg.brute_attempts))),
                                   f"{len(c.login)} login attempts ({len(c.fails)} rejected) in {cfg.brute_window:.0f}s", f"{len(c.login)} attempts/{cfg.brute_window:.0f}s", "behaviour"))
            if ev["status"] in (404, 403) and not static and len(c.errors) >= cfg.recon_errors and len({p for _, p in c.errors}) >= cfg.recon_distinct_paths:
                n = len(c.errors)
                hits.append(WebHit("Web Reconnaissance", "WEB-BEH-SCAN", min(0.96, 0.80 + 0.16 * min(1.0, n / (4 * cfg.recon_errors))),
                                   f"{n} not-found/forbidden answers on {len({p for _, p in c.errors})} different paths in {cfg.recon_window:.0f}s (directory scan)",
                                   f"{n} errors/{cfg.recon_window:.0f}s", "behaviour"))
        return hits
