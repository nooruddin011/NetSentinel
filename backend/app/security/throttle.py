"""In-memory login throttle: lock a (username, ip) key after repeated failures.

Protects the platform's own login endpoint against the very attack it detects (brute force).
For multi-process deployments, back this with Redis instead.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class LoginThrottle:
    def __init__(self, max_failures: int = 5, window_seconds: int = 900):
        self.max_failures = max_failures
        self.window = window_seconds
        self._fails = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key, now):
        q = self._fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def retry_after(self, key: str) -> int:
        """Seconds until the key may try again (0 when not locked)."""
        with self._lock:
            now = time.time()
            q = self._prune(key, now)
            if len(q) >= self.max_failures:
                return max(1, int(self.window - (now - q[0])))
            return 0

    def failure(self, key: str) -> None:
        with self._lock:
            now = time.time()
            self._prune(key, now).append(now)

    def success(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
