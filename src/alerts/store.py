"""Append-only SQLite alert history with a write-behind queue.

Writes happen on a dedicated thread so the detection hot path never blocks on
disk IO. If the queue overflows (e.g. disk removed), events are dropped and
counted rather than stalling detection.
"""
from __future__ import annotations

import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            TEXT PRIMARY KEY,
    ts_first      REAL NOT NULL,
    ts_last       REAL NOT NULL,
    label         TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    src           TEXT NOT NULL,
    sport         INTEGER NOT NULL,
    dst           TEXT NOT NULL,
    dport         INTEGER NOT NULL,
    proto         TEXT NOT NULL,
    occurrences   INTEGER NOT NULL DEFAULT 1,
    flow_duration_us INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts (ts_last DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev   ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_label ON alerts (label);
"""


class SqliteAlertStore:
    def __init__(self, path: str | Path, queue_size: int = 10_000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._writer_loop,
                                        name="ut-alert-db", daemon=True)
        self._thread.start()

    # -- hot path (called from detection threads) ------------------------------

    def enqueue_upsert(self, alert: dict) -> None:
        try:
            self._queue.put_nowait(("upsert", alert))
        except queue.Full:
            self.dropped += 1

    # -- writer thread ------------------------------------------------------------

    def _writer_loop(self) -> None:
        pending: list[tuple[str, dict]] = []
        while not self._stop.is_set():
            try:
                pending.append(self._queue.get(timeout=0.5))
            except queue.Empty:
                pass
            while True:
                try:
                    pending.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            if pending:
                try:
                    self._apply(pending)
                except sqlite3.Error:
                    self.dropped += len(pending)
                pending = []
        # final drain
        while True:
            try:
                pending.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if pending:
            try:
                self._apply(pending)
            except sqlite3.Error:
                self.dropped += len(pending)

    def _apply(self, batch: list[tuple[str, dict]]) -> None:
        upserts = [alert for op, alert in batch if op == "upsert"]
        if not upserts:
            return
        self._conn.executemany(
            """
            INSERT INTO alerts (id, ts_first, ts_last, label, category, severity,
                                confidence, src, sport, dst, dport, proto,
                                occurrences, flow_duration_us)
            VALUES (:id, :ts_first, :ts_last, :label, :category, :severity,
                    :confidence, :src, :sport, :dst, :dport, :proto_name,
                    :occurrences, :flow_duration_us)
            ON CONFLICT(id) DO UPDATE SET
                ts_last = excluded.ts_last,
                occurrences = excluded.occurrences,
                confidence = MAX(confidence, excluded.confidence)
            """,
            upserts,
        )
        self._conn.commit()

    # -- queries -------------------------------------------------------------------

    def query(self, severity: Optional[str] = None, label: Optional[str] = None,
              limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts"
        where: list[str] = []
        params: list[Any] = []
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if label:
            where.append("label = ?")
            params.append(label)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts_last DESC LIMIT ? OFFSET ?"
        params += [int(limit), int(offset)]
        cur = self._conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count(self, severity: Optional[str] = None, label: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) FROM alerts"
        where: list[str] = []
        params: list[Any] = []
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if label:
            where.append("label = ?")
            params.append(label)
        if where:
            sql += " WHERE " + " AND ".join(where)
        return int(self._conn.execute(sql, params).fetchone()[0])

    def stats(self) -> dict:
        by_severity = {row[0]: row[1] for row in self._conn.execute(
            "SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
        by_label = {row[0]: row[1] for row in self._conn.execute(
            "SELECT label, COUNT(*) FROM alerts GROUP BY label ORDER BY 2 DESC")}
        return {"by_severity": by_severity, "by_label": by_label,
                "total": sum(by_severity.values()), "dropped": self.dropped}

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        try:
            self._conn.commit()
            self._conn.close()
        except sqlite3.Error:
            pass
