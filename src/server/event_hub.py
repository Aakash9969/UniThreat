"""Thread -> asyncio event bridge.

The capture pipeline runs on its own threads; the dashboard listens on a
FastAPI event loop. ``EventHub.publish`` is called from pipeline threads and
safely fans events out to every connected WebSocket client.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Optional

_QUEUE_SIZE = 500


class EventHub:
    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._clients: set[asyncio.Queue] = set()
        self._lock = threading.Lock()
        self.published = 0
        self.dropped = 0

    # -- server side ------------------------------------------------------------

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_SIZE)
        with self._lock:
            self._clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._clients.discard(q)

    @property
    def n_clients(self) -> int:
        with self._lock:
            return len(self._clients)

    # -- pipeline side -------------------------------------------------------------

    def publish(self, event: dict) -> None:
        """Thread-safe; called from capture/inference threads."""
        loop = self._loop
        self.published += 1
        if loop is None or loop.is_closed():
            self.dropped += 1
            return
        try:
            loop.call_soon_threadsafe(self._fanout, event)
        except RuntimeError:  # loop shutting down
            self.dropped += 1

    def _fanout(self, event: dict) -> None:
        with self._lock:
            clients = list(self._clients)
        for q in clients:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # slow client: drop the oldest event and push the newest
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass
                self.dropped += 1
