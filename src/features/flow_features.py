"""Online feature accumulation for a single unidirectional flow.

Produces the canonical feature vector defined in ``src/features/schema.py``
directly from a stream of :class:`PacketInfo`. Because the sensor only ever
sees one direction, "flow" and "forward" inter-arrival statistics coincide by
construction — this matches the one-way semantics of a data-diode deployment.

Numeric conventions (kept as close to CICFlowMeter as practical):
  * inter-arrival times / durations in microseconds
  * rates as bytes (packets) per second
  * standard deviations use the population formula (ddof=0)
"""
from __future__ import annotations

import math
from typing import TYPE_CHECKING

from src.features.schema import CANONICAL_FEATURES

if TYPE_CHECKING:  # runtime import would be circular (capture -> features)
    from src.capture.packet_info import PacketInfo

IPPROTO_TCP = 6  # keep in sync with src.capture.packet_info

# TCP flag bit positions (matches Scapy's flag value bits)
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

FlowKey = tuple[str, int, str, int, int]  # src, sport, dst, dport, proto


class RunningStats:
    """Welford-style online mean/std/min/max (population std, ddof=0)."""

    __slots__ = ("n", "mean", "m2", "mn", "mx")

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.mn = math.inf
        self.mx = -math.inf

    def add(self, x: float) -> None:
        self.n += 1
        if x < self.mn:
            self.mn = x
        if x > self.mx:
            self.mx = x
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / self.n) if self.n > 0 else 0.0

    @property
    def min(self) -> float:
        return self.mn if self.n > 0 else 0.0

    @property
    def max(self) -> float:
        return self.mx if self.n > 0 else 0.0

    def summary(self) -> tuple[float, float, float, float]:
        """(mean, std, max, min) with 0.0 defaults when empty."""
        if self.n == 0:
            return 0.0, 0.0, 0.0, 0.0
        return self.mean, self.std, self.mx, self.mn


class CompletedFlow:
    """A finished flow plus its extracted features and light metadata."""

    __slots__ = ("key", "first_ts", "last_ts", "reason", "n_packets", "n_bytes",
                 "features")

    def __init__(self, key: FlowKey, first_ts: int, last_ts: int, reason: str,
                 n_packets: int, n_bytes: int, features: dict[str, float]):
        self.key = key
        self.first_ts = first_ts
        self.last_ts = last_ts
        self.reason = reason            # idle_timeout | active_timeout | final | overflow
        self.n_packets = n_packets
        self.n_bytes = n_bytes
        self.features = features

    @property
    def src(self) -> str:
        return self.key[0]

    @property
    def sport(self) -> int:
        return self.key[1]

    @property
    def dst(self) -> str:
        return self.key[2]

    @property
    def dport(self) -> int:
        return self.key[3]

    @property
    def proto(self) -> int:
        return self.key[4]

    def to_record(self) -> dict:
        return {
            "src": self.src, "sport": self.sport,
            "dst": self.dst, "dport": self.dport,
            "proto": self.proto,
            "first_ts": self.first_ts, "last_ts": self.last_ts,
            "duration_us": self.features["duration_us"],
            "packets": self.n_packets, "bytes": self.n_bytes,
            "reason": self.reason,
        }


class FlowAccumulator:
    """Statefully folds packets of ONE unidirectional 5-tuple flow."""

    __slots__ = (
        "key", "epoch", "first_ts", "last_ts", "n_packets", "n_bytes",
        "idle_us_threshold", "_len_stats", "_iat_stats", "_payload_stats",
        "_active_stats", "_idle_stats", "iat_total", "header_bytes",
        "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr",
        "data_packets", "init_win", "_period_start", "_last_pushed_ts",
    )

    # Idle/active period granularity for heap pushes (precision trade-off):
    HEAP_PUSH_INTERVAL_US = 1_000_000

    def __init__(self, key: FlowKey, idle_us_threshold: int = 5_000_000):
        self.key = key
        self.epoch = 0
        self.first_ts = -1
        self.last_ts = -1
        self.n_packets = 0
        self.n_bytes = 0
        self.idle_us_threshold = idle_us_threshold
        self._len_stats = RunningStats()      # per-packet IP total length
        self._iat_stats = RunningStats()      # inter-arrival times
        self._payload_stats = RunningStats()  # payload sizes of data packets
        self._active_stats = RunningStats()   # active-period durations
        self._idle_stats = RunningStats()      # idle-gap durations
        self.iat_total = 0
        self.header_bytes = 0
        self.fin = self.syn = self.rst = self.psh = 0
        self.ack = self.urg = self.ece = self.cwr = 0
        self.data_packets = 0
        self.init_win = 0
        self._period_start = -1               # current active period start
        self._last_pushed_ts = -1             # last ts pushed onto expiry heap

    # -- ingestion ----------------------------------------------------------

    def add(self, pkt: PacketInfo) -> None:
        ts = pkt.ts_us
        if self.n_packets == 0:
            self.first_ts = ts
            self._period_start = ts  # a flow always starts inside an active period
        else:
            iat = ts - self.last_ts
            self._iat_stats.add(iat)
            self.iat_total += iat
            if iat > self.idle_us_threshold:
                # close the active period at the previous packet, then count
                # the whole silence as one idle period, then resume activity.
                self._active_stats.add(self.last_ts - self._period_start)
                self._idle_stats.add(iat)
                self._period_start = ts

        self.last_ts = ts
        self.n_packets += 1
        self.n_bytes += pkt.ip_total_len
        self._len_stats.add(pkt.ip_total_len)
        self.header_bytes += pkt.header_bytes

        if pkt.proto == IPPROTO_TCP:
            f = pkt.tcp_flags
            if f & FIN:
                self.fin += 1
            if f & SYN:
                self.syn += 1
            if f & RST:
                self.rst += 1
            if f & PSH:
                self.psh += 1
            if f & ACK:
                self.ack += 1
            if f & URG:
                self.urg += 1
            if f & ECE:
                self.ece += 1
            if f & CWR:
                self.cwr += 1
            if self.n_packets == 1:
                self.init_win = pkt.tcp_win

        if pkt.payload_len > 0:
            self.data_packets += 1
            self._payload_stats.add(pkt.payload_len)

    # -- completion ---------------------------------------------------------

    def finish(self, reason: str) -> CompletedFlow:
        # Close the trailing active period. Note: when the final packet
        # follows an idle gap (or the flow has a single packet) this closes a
        # zero-length burst — an isolated probe counts as an instant of
        # activity, which is exactly what slow-rate attacks look like.
        if self.n_packets > 0:
            self._active_stats.add(self.last_ts - self._period_start)

        duration_us = self.last_ts - self.first_ts if self.n_packets > 0 else 0
        if duration_us > 0:
            bytes_per_s = self.n_bytes * 1e6 / duration_us
            packets_per_s = self.n_packets * 1e6 / duration_us
        else:
            # Single-packet (or zero-duration) flows have no measurable rate.
            # The dataset encodes these as inf; we deliberately use 0.0 so the
            # live pipeline stays numerically clean.
            bytes_per_s = 0.0
            packets_per_s = 0.0

        iat_mean, iat_std, iat_max, iat_min = self._iat_stats.summary()
        active_mean, active_std, active_max, active_min = self._active_stats.summary()
        idle_mean, idle_std, idle_max, idle_min = self._idle_stats.summary()
        len_mean, len_std, len_max, len_min = self._len_stats.summary()

        features = {
            "protocol": float(self.key[4]),
            "duration_us": float(duration_us),
            "fwd_packets": float(self.n_packets),
            "fwd_bytes": float(self.n_bytes),
            "fwd_pkt_len_max": float(len_max),
            "fwd_pkt_len_min": float(len_min),
            "fwd_pkt_len_mean": len_mean,
            "fwd_pkt_len_std": len_std,
            "flow_bytes_per_s": bytes_per_s,
            "flow_packets_per_s": packets_per_s,
            "flow_iat_mean": iat_mean,
            "flow_iat_std": iat_std,
            "flow_iat_max": iat_max,
            "flow_iat_min": iat_min,
            "fwd_iat_tot": float(self.iat_total),
            "fwd_iat_mean": iat_mean,
            "fwd_iat_std": iat_std,
            "fwd_iat_max": iat_max,
            "fwd_iat_min": iat_min,
            "fwd_psh_flags": float(self.psh),
            "fwd_urg_flags": float(self.urg),
            "fwd_header_bytes": float(self.header_bytes),
            "fwd_packets_per_s": packets_per_s,
            "fin_flag_count": float(self.fin),
            "syn_flag_count": float(self.syn),
            "rst_flag_count": float(self.rst),
            "psh_flag_count": float(self.psh),
            "ack_flag_count": float(self.ack),
            "urg_flag_count": float(self.urg),
            "cwr_flag_count": float(self.cwr),
            "ece_flag_count": float(self.ece),
            "fwd_seg_size_avg": self._payload_stats.mean if self.data_packets else 0.0,
            "init_win_bytes_fwd": float(self.init_win),
            "act_data_pkt_fwd": float(self.data_packets),
            "min_seg_size_fwd": self._payload_stats.min if self.data_packets else 0.0,
            "active_mean": active_mean,
            "active_std": active_std,
            "active_max": active_max,
            "active_min": active_min,
            "idle_mean": idle_mean,
            "idle_std": idle_std,
            "idle_max": idle_max,
            "idle_min": idle_min,
        }
        assert set(features) == set(CANONICAL_FEATURES), \
            "live feature vector drifted from the canonical schema"

        return CompletedFlow(
            key=self.key, first_ts=self.first_ts, last_ts=self.last_ts,
            reason=reason, n_packets=self.n_packets, n_bytes=self.n_bytes,
            features=features,
        )
