"""Token-bucket rate limiter (per key), thread-safe. Used to cap how fast one connector can push events."""
from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, capacity: float, refill_per_second: float):
        self.capacity, self.rate = float(capacity), float(refill_per_second)
        self._state = {}  # key -> [tokens, last_timestamp]
        self._lock = threading.Lock()

    def allow(self, key, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if cost > tokens:
                self._state[key] = [tokens, now]
                return False
            self._state[key] = [tokens - cost, now]
            if len(self._state) > 10000:  # bound memory
                self._state.pop(next(iter(self._state)))
            return True

    def retry_after(self, key, cost: float = 1.0) -> int:
        with self._lock:
            tokens, _ = self._state.get(key, (self.capacity, time.monotonic()))
        return max(1, int((cost - tokens) / self.rate) + 1) if self.rate else 60
