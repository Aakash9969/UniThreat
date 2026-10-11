"""Capture pipeline: packets -> unidirectional flows -> ML verdicts -> alerts.

Threading model (all started by :meth:`CapturePipeline.start`):

  ingest thread   — runs the source; applies the direction filter, updates
                    flow-table + packet stats, advances the virtual clock
  poller thread   — every 0.5s closes expired flows into a completion queue
  inference thread— consumes completions, runs the ML detector, appends to the
                    recent-flow ring, raises alerts, emits throttled events

The pipeline is deliberately detector-agnostic and sink-agnostic: pass a
``detector`` (src.ml.detector.ThreatDetector), an ``alert_manager`` and an
``on_event`` callback and it becomes a complete IDS pipeline; omit them and it
is a pure flow exporter (used by scripts/replay_pcap.py).
"""
from __future__ import annotations

import threading
import time
from collections import Counter, deque
from typing import Callable, Optional

from src.capture.direction import DirectionFilter
from src.capture.flow_table import FlowTable
from src.capture.packet_info import PacketInfo
from src.capture.source import BaseSource
from src.config import FlowConfig
from src.features.flow_features import CompletedFlow

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 132: "SCTP"}

EventCallback = Callable[[dict], None]


def _proto_name(num: int) -> str:
    return PROTO_NAMES.get(num, str(num))


class CapturePipeline:
    def __init__(
        self,
        source: BaseSource,
        flow_cfg: FlowConfig,
        direction_filter: Optional[DirectionFilter] = None,
        detector=None,
        alert_manager=None,
        on_event: Optional[EventCallback] = None,
        flow_events_per_s: int = 200,
        recent_flow_capacity: int = 2000,
        history_seconds: int = 120,
    ):
        self.source = source
        self.flow_cfg = flow_cfg
        self.direction_filter = direction_filter or DirectionFilter("any")
        self.detector = detector
        self.alert_manager = alert_manager
        self.on_event = on_event
        self._flow_events_per_s = max(0, flow_events_per_s)
        self.history_seconds = history_seconds

        self.table = FlowTable(flow_cfg)
        self._completions: deque[CompletedFlow] = deque(maxlen=5000)
        self._recent_flows: deque[dict] = deque(maxlen=recent_flow_capacity)

        self._running = False
        self._stop_event = threading.Event()
        self._clock_us = 0
        self._flow_seq = 0

        self._stats_lock = threading.Lock()
        self._sec_buckets: dict[int, tuple[int, int]] = {}
        self._by_label: Counter[str] = Counter()
        self.packets_total = 0
        self.bytes_total = 0
        self.flows_total = 0
        self.threats_total = 0
        self.completions_dropped = 0
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None

        self._threads: list[threading.Thread] = []
        self._event_tokens = 0.0
        self._last_token_refill = 0.0
        self._stopping = False

    # -- lifecycle -------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self.started_at = time.time()
        self.stopped_at = None

        threads = [
            threading.Thread(target=self._ingest_loop, name="ut-ingest", daemon=True),
            threading.Thread(target=self._poller_loop, name="ut-poller", daemon=True),
            threading.Thread(target=self._inference_loop, name="ut-inference", daemon=True),
        ]
        self._threads = threads
        for t in threads:
            t.start()
        self._emit({"type": "capture_started", "source": self.source.name,
                    "direction": self.direction_filter.describe()})

    def stop(self, flush: bool = True) -> None:
        if not self._running:
            return
        self._stopping = True
        self._running = False
        self._stop_event.set()
        try:
            self.source.stop()
        except Exception:
            pass
        ingest = next((t for t in self._threads if t.name == "ut-ingest"), None)
        if ingest is not None:
            ingest.join(timeout=10.0)

        # No more input — drain everything (the ingest thread normally already
        # finalised on exit; this is a safety net for crashed sources).
        if flush:
            self._finalize()

        for t in self._threads:
            if t is not ingest:
                t.join(timeout=5.0)
        self.stopped_at = time.time()
        self._emit({"type": "capture_stopped", "source": self.source.name})

    # -- ingestion --------------------------------------------------------------

    def _ingest_loop(self) -> None:
        try:
            self.source.run(
                sink=self._handle_packet,
                stop_event=self._stop_event,
                on_finished=self._source_finished,
            )
        except Exception as exc:
            self._emit({"type": "capture_error", "error": str(exc)})
        finally:
            self._stop_event.set()
            self._finalize()

    def _finalize(self) -> None:
        """Drain pending completions and close every active flow exactly once."""
        leftover = self.table.flush_all("final")
        with self._stats_lock:
            queued = list(self._completions)
            self._completions.clear()
        for cf in queued + leftover:
            self._process_completion(cf)
        if not self._stopping:
            # source ended on its own (replay finished / live capture died)
            self._running = False
            self.stopped_at = time.time()
            self._emit({"type": "capture_stopped", "source": self.source.name})

    def _handle_packet(self, pkt: PacketInfo) -> None:
        if self._stop_event.is_set():
            return
        if not self.direction_filter.allows(pkt):
            return
        with self._stats_lock:
            self.packets_total += 1
            self.bytes_total += pkt.ip_total_len
            sec = pkt.ts_us // 1_000_000
            pk, by = self._sec_buckets.get(sec, (0, 0))
            self._sec_buckets[sec] = (pk + 1, by + pkt.ip_total_len)
            if len(self._sec_buckets) > self.history_seconds * 4:
                cutoff = sec - self.history_seconds * 2
                for s in [s for s in self._sec_buckets if s < cutoff]:
                    del self._sec_buckets[s]
        if pkt.ts_us > self._clock_us:
            self._clock_us = pkt.ts_us
        self.table.update(pkt)

    def _source_finished(self) -> None:
        """Replay sources call this when the file ends (non-loop mode)."""
        self._emit({"type": "source_finished"})

    # -- expiry / inference ------------------------------------------------------

    def _poller_loop(self) -> None:
        while not self._stop_event.wait(timeout=0.5):
            if self.source.provides_wall_clock:
                now = int(time.time() * 1_000_000)
            else:
                now = self._clock_us
            for cf in self.table.poll_expired(now):
                with self._stats_lock:
                    if len(self._completions) >= self._completions.maxlen:
                        self._completions.popleft()
                        self.completions_dropped += 1
                    self._completions.append(cf)

    def _inference_loop(self) -> None:
        while not self._stop_event.is_set():
            cf: Optional[CompletedFlow] = None
            with self._stats_lock:
                if self._completions:
                    cf = self._completions.popleft()
            if cf is None:
                time.sleep(0.05)
                continue
            try:
                self._process_completion(cf)
            except Exception as exc:  # never let one bad flow kill detection
                self._emit({"type": "pipeline_error", "error": str(exc)})

    def _process_completion(self, cf: CompletedFlow) -> None:
        verdict = None
        if self.detector is not None:
            verdict = self.detector.detect(cf.features)

        with self._stats_lock:
            self._flow_seq += 1
            flow_id = self._flow_seq
            self.flows_total += 1
            label = verdict.label if verdict else "N/A"
            self._by_label[label] += 1
            is_threat = bool(verdict and verdict.is_threat)
            if is_threat:
                self.threats_total += 1

        record = cf.to_record()
        record.update({
            "id": flow_id,
            "ts": time.time(),
            "proto_name": _proto_name(cf.proto),
            "verdict": verdict.to_dict() if verdict else None,
        })
        self._recent_flows.append(record)

        if is_threat and self.alert_manager is not None:
            alert, created = self.alert_manager.add(record, verdict)
            self._emit({"type": "alert", "alert": alert, "new": created})

        self._maybe_emit_flow(record)

    def _maybe_emit_flow(self, record: dict) -> None:
        if self._flow_events_per_s <= 0:
            return
        now = time.time()
        if now - self._last_token_refill >= 1.0:
            self._event_tokens = float(self._flow_events_per_s)
            self._last_token_refill = now
        if self._event_tokens >= 1.0:
            self._event_tokens -= 1.0
            self._emit({"type": "flow", "flow": record})

    def _emit(self, event: dict) -> None:
        cb = self.on_event
        if cb is None:
            return
        try:
            cb(event)
        except Exception:
            pass  # event sinks must never break the pipeline

    # -- introspection -------------------------------------------------------------

    def snapshot_stats(self) -> dict:
        with self._stats_lock:
            timeline = [
                {"sec": sec, "packets": pk, "bytes": by}
                for sec, (pk, by) in sorted(self._sec_buckets.items())
            ][-self.history_seconds * 2:]
            return {
                "running": self._running,
                "source": self.source.name,
                "direction": self.direction_filter.describe(),
                "started_at": self.started_at,
                "stopped_at": self.stopped_at,
                "packets_total": self.packets_total,
                "bytes_total": self.bytes_total,
                "flows_total": self.flows_total,
                "flows_active": self.table.n_active,
                "threats_total": self.threats_total,
                "completions_dropped": self.completions_dropped,
                "timeline": timeline,
                "flows_by_label": dict(self._by_label),
            }

    def recent_flows(self, limit: int = 50, offset: int = 0,
                    only_threats: bool = False) -> list[dict]:
        out: list[dict] = []
        for record in reversed(self._recent_flows):
            if only_threats and not (record["verdict"] and record["verdict"]["is_threat"]):
                continue
            if offset > 0:
                offset -= 1
                continue
            out.append(record)
            if len(out) >= limit:
                break
        return out
