"""Thread-safe fan-out hub for live events (detection runs in worker threads, sockets live on the loop)."""
from __future__ import annotations

import asyncio


class Hub:
    def __init__(self):
        self._clients: dict = {}
        self._loop = None

    def bind(self, loop):
        self._loop = loop

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def client_count_for(self, workspace_id) -> int:
        return sum(1 for wid in self._clients.values() if wid == workspace_id)

    def register(self, workspace_id=1) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._clients[q] = workspace_id
        return q

    def unregister(self, q):
        self._clients.pop(q, None)

    def publish(self, message: dict):
        """Safe to call from any thread."""
        if self._loop is None or not self._clients:
            return
        self._loop.call_soon_threadsafe(self._fanout, message)

    def _fanout(self, message):
        workspace_id = message.get("workspace_id")
        for q, wid in list(self._clients.items()):
            if (workspace_id if workspace_id is not None else 1) != wid:
                continue
            if q.full():  # slow consumer: drop the oldest message rather than block detection
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait({k: v for k, v in message.items() if k != "workspace_id"})
