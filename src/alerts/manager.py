"""Alert manager: deduplication, in-memory ring, persistence, severity stats.

An "alert" is a sustained threat verdict; the same threat class hitting the
same src->dst endpoint repeatedly inside ``dedup_window_s`` collapses into a
single alert whose ``occurrences`` counter grows.
"""
from __future__ import annotations

import threading
import time
import uuid
from collections import Counter, deque
from typing import Optional

from src.alerts.store import SqliteAlertStore
from src.ml.detector import DetectionResult

_FLOW_FIELDS = ("src", "sport", "dst", "dport", "proto_name", "flow_duration_us")


def _flow_duration(flow: dict) -> int:
    try:
        return int(flow.get("duration_us", 0))
    except (TypeError, ValueError):
        return 0


class AlertManager:
    def __init__(self, dedup_window_s: float = 60.0, max_recent: int = 2000,
                 store: Optional[SqliteAlertStore] = None):
        self.dedup_window_s = float(dedup_window_s)
        self.store = store
        self._lock = threading.Lock()
        self._recent: deque[dict] = deque(maxlen=max_recent)
        self._dedup: dict[tuple, dict] = {}
        self._by_severity: Counter[str] = Counter()
        self._by_label: Counter[str] = Counter()
        self.total_created = 0

    # -- ingestion ---------------------------------------------------------------

    def add(self, flow: dict, detection: DetectionResult) -> tuple[dict, bool]:
        """Register a threat verdict. Returns (alert, created_new)."""
        now = time.time()
        key = (detection.label, flow["src"], flow["sport"],
               flow["dst"], flow["dport"])

        with self._lock:
            existing = self._dedup.get(key)
            if existing is not None and now - existing["ts_last"] <= self.dedup_window_s:
                existing["ts_last"] = now
                existing["occurrences"] += 1
                existing["confidence"] = max(existing["confidence"],
                                              detection.confidence)
                self._queue_persist(existing)
                return dict(existing), False

            alert = {
                "id": uuid.uuid4().hex[:12],
                "ts_first": now,
                "ts_last": now,
                "label": detection.label,
                "category": detection.category,
                "severity": detection.severity,
                "confidence": detection.confidence,
                "src": flow["src"],
                "sport": int(flow["sport"]),
                "dst": flow["dst"],
                "dport": int(flow["dport"]),
                "proto_name": flow.get("proto_name", "?"),
                "occurrences": 1,
                "flow_duration_us": _flow_duration(flow),
            }
            self._dedup[key] = alert
            self._recent.append(alert)
            self._by_severity[detection.severity] += 1
            self._by_label[detection.label] += 1
            self.total_created += 1
            self._queue_persist(alert)
            return dict(alert), True

    def _queue_persist(self, alert: dict) -> None:
        if self.store is not None:
            self.store.enqueue_upsert(alert)

    # -- queries -----------------------------------------------------------------

    def list_recent(self, limit: int = 100, offset: int = 0,
                    severity: Optional[str] = None) -> list[dict]:
        with self._lock:
            items = list(self._recent)
        items.reverse()  # newest first
        out: list[dict] = []
        for alert in items:
            if severity and alert["severity"] != severity:
                continue
            if offset > 0:
                offset -= 1
                continue
            out.append(alert)
            if len(out) >= limit:
                break
        return out

    def summary(self) -> dict:
        with self._lock:
            by_severity = dict(self._by_severity)
            by_label = dict(self._by_label)
            total = self.total_created
        if self.store is not None:
            dropped = self.store.dropped
        else:
            dropped = 0
        return {
            "total_created": total,
            "by_severity": by_severity,
            "by_label": by_label,
            "persistence_dropped": dropped,
            "persisted": self.store is not None,
        }

    # -- lifecycle -----------------------------------------------------------------

    def close(self) -> None:
        if self.store is not None:
            self.store.close()
