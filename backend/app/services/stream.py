"""Thread-safe fan-out hub for live events (detection runs in worker threads, sockets live on the loop)."""
from __future__ import annotations

import asyncio


class Hub:
    def __init__(self):
        self._clients: set = set()
        self._loop = None

    def bind(self, loop):
        self._loop = loop

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def register(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._clients.add(q)
        return q

    def unregister(self, q):
        self._clients.discard(q)

    def publish(self, message: dict):
        """Safe to call from any thread."""
        if self._loop is None or not self._clients:
            return
        self._loop.call_soon_threadsafe(self._fanout, message)

    def _fanout(self, message):
        for q in list(self._clients):
            if q.full():  # slow consumer: drop the oldest message rather than block detection
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(message)
