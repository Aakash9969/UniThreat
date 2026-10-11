"""Unidirectional flow tracking with idle/active expiry.

Flows are keyed by the one-way 5-tuple (src, sport, dst, dport, proto) —
reverse-direction packets belong to a *different* flow, mirroring what a
sensor behind a data diode observes. Expiry uses lazy-validated min-heaps:

  * idle heap  — entry (last_ts, epoch, key); a flow expires when its most
                 recently pushed timestamp is older than ``idle_timeout``
  * active heap — entry (first_ts + active_timeout, epoch, key); a flow
                 expires after being alive too long even if still active

Heap entries may go stale (flow re-created with a new epoch, or a newer
timestamp pushed); they are validated against the accumulator's ``epoch``
and ``_last_pushed_ts`` before expiring anything. Idle checkpoints are pushed
at most once per second per flow, so expiry precision is ~1s.
"""
from __future__ import annotations

import heapq
import threading
from typing import Iterator

from src.capture.packet_info import PacketInfo
from src.config import FlowConfig
from src.features.flow_features import CompletedFlow, FlowAccumulator, FlowKey


class FlowTable:
    def __init__(self, flow_cfg: FlowConfig):
        self.cfg = flow_cfg
        self.idle_us = int(flow_cfg.idle_timeout_s * 1_000_000)
        self.active_us = int(flow_cfg.active_timeout_s * 1_000_000)
        self.idle_period_us = int(flow_cfg.active_idle_threshold_s * 1_000_000)
        self.max_flows = flow_cfg.max_concurrent_flows

        self._flows: dict[FlowKey, FlowAccumulator] = {}
        self._idle_heap: list[tuple[int, int, FlowKey]] = []
        self._active_heap: list[tuple[int, int, FlowKey]] = []
        self._epoch = 0
        self._overflowed: list[CompletedFlow] = []
        self._lock = threading.Lock()

    # -- ingestion -----------------------------------------------------------

    def update(self, pkt: PacketInfo) -> None:
        key: FlowKey = (pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto)
        with self._lock:
            acc = self._flows.get(key)
            if acc is None:
                acc = FlowAccumulator(key, idle_us_threshold=self.idle_period_us)
                self._epoch += 1
                acc.epoch = self._epoch
                self._flows[key] = acc
                if len(self._flows) > self.max_flows:
                    self._evict_oldest_locked()

            acc.add(pkt)

            if acc.n_packets == 1:
                heapq.heappush(self._active_heap,
                               (acc.first_ts + self.active_us, acc.epoch, key))
            # Push an idle-heap checkpoint on the first packet and then at
            # most once per interval, to keep heap memory bounded; stale
            # entries are discarded by validation below.
            if acc.n_packets == 1 or \
                    acc.last_ts - acc._last_pushed_ts >= FlowAccumulator.HEAP_PUSH_INTERVAL_US:
                acc._last_pushed_ts = acc.last_ts
                heapq.heappush(self._idle_heap, (acc.last_ts, acc.epoch, key))

    def _evict_oldest_locked(self) -> None:
        """Memory guard: finish+drop the most idle flow when the table is full."""
        while self._idle_heap:
            ts, epoch, key = heapq.heappop(self._idle_heap)
            acc = self._flows.get(key)
            if acc is not None and acc.epoch == epoch and acc._last_pushed_ts == ts:
                del self._flows[key]
                self._overflowed.append(acc.finish("overflow"))
                return
        # No valid heap entry (pathological, e.g. everything brand new):
        # fall back to dropping the flow with the smallest first timestamp.
        if self._flows:
            key = min(self._flows, key=lambda k: self._flows[k].first_ts)
            acc = self._flows.pop(key)
            self._overflowed.append(acc.finish("overflow"))

    # -- expiry ---------------------------------------------------------------

    def poll_expired(self, now_us: int) -> list[CompletedFlow]:
        """Close and return flows that expired as of ``now_us`` (virtual clock)."""
        with self._lock:
            return self._poll_locked(now_us)

    def _poll_locked(self, now_us: int) -> list[CompletedFlow]:
        finished: list[CompletedFlow] = self._overflowed
        self._overflowed = []

        idle_cutoff = now_us - self.idle_us
        while self._idle_heap and self._idle_heap[0][0] <= idle_cutoff:
            ts, epoch, key = heapq.heappop(self._idle_heap)
            acc = self._flows.get(key)
            if acc is None or acc.epoch != epoch:
                continue  # stale entry
            if acc._last_pushed_ts != ts:
                continue  # a newer checkpoint exists; entry superseded
            del self._flows[key]
            finished.append(acc.finish("idle_timeout"))

        while self._active_heap and self._active_heap[0][0] <= now_us:
            _, epoch, key = heapq.heappop(self._active_heap)
            acc = self._flows.get(key)
            if acc is None or acc.epoch != epoch:
                continue
            del self._flows[key]
            finished.append(acc.finish("active_timeout"))

        return finished

    def flush_all(self, reason: str = "final") -> list[CompletedFlow]:
        """Close every active flow (used at shutdown / end of replay)."""
        with self._lock:
            flows = list(self._flows.values())
            self._flows.clear()
            self._idle_heap.clear()
            self._active_heap.clear()
            finished = self._overflowed
            self._overflowed = []
        finished.extend(acc.finish(reason) for acc in flows)
        return finished

    # -- introspection ---------------------------------------------------------

    @property
    def n_active(self) -> int:
        return len(self._flows)

    def snapshot_keys(self) -> Iterator[FlowKey]:
        with self._lock:
            yield from list(self._flows.keys())
