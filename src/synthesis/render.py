"""Flow synthesis: turn dataset feature rows back into packets.

`render_flow_packets` reconstructs a packet sequence from a canonical
CIC-IDS2017 flow row such that the sensor's own :class:`FlowAccumulator`
recomputes a feature vector close to the row's original values.

This module is the backbone of two tools:

* ``scripts/render_flows.py`` — write rendered flows into a replayable pcap
  (demo traffic that the model actually detects);
* ``src.ml.train`` in "live features" mode — train the model on features
  produced by the *live extractor* from rendered dataset flows, guaranteeing
  train/serve consistency (the CICFlowMeter CSV columns carry capture-tool
  artefacts — e.g. 2-byte "packet lengths" — that no physical packet can
  reproduce, which otherwise skews the model towards impossible values).
"""
from __future__ import annotations

import random
from typing import Optional

from src.capture.packet_info import IPPROTO_TCP, IPPROTO_UDP, PacketInfo

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

MIN_PHYSICAL_LEN = 40  # 20B IP + 20B TCP


def _f(row: dict, name: str, default: float = 0.0) -> float:
    try:
        v = float(row.get(name, default))
    except (TypeError, ValueError):
        return default
    return v if v == v else default  # NaN guard


def reconstruct_lengths(n: int, mn: float, mx: float, mean: float) -> list[int]:
    """Reconstruct n packet lengths honouring the row's min/max/mean."""
    mn = max(mn, MIN_PHYSICAL_LEN)
    mx = max(mx, mn)
    if mx <= mn:
        lengths = [mn] * n
    else:
        k = int(round(n * (mean - mn) / (mx - mn)))
        k = max(0, min(n, k))
        lengths = [mx] * k + [mn] * (n - k)
    return [max(int(v), MIN_PHYSICAL_LEN) for v in lengths]


def _flags_for(n: int, syn_c: int, ack_c: int, psh_c: int, fin_c: int,
               rst_c: int, urg_c: int) -> list[int]:
    flags = [0] * n
    if syn_c >= 1:
        flags[0] |= TCP_SYN
    if ack_c >= 1:
        for i in range(min(ack_c, n)):
            flags[i] |= TCP_ACK
    if psh_c >= 1:
        for i in range(min(psh_c, n)):
            flags[i] |= TCP_PSH
    if urg_c >= 1:
        for i in range(min(urg_c, n)):
            flags[i] |= TCP_URG
    if rst_c >= 1:
        flags[-1] |= TCP_RST
    if fin_c >= 1:
        flags[-1] |= TCP_FIN
    if not any(flags):
        flags = [TCP_ACK | TCP_PSH] * n
    return flags


def _gaps_for(n: int, duration_us: float, iat_max_us: float,
              idle_max_us: float) -> list[float]:
    """Inter-packet gaps in SECONDS honouring duration, iat_max and idle_max."""
    if n <= 1:
        return []
    duration = max(duration_us, 0.0)               # microseconds
    gaps_us = [duration / (n - 1)] * (n - 1)
    big = max(idle_max_us, iat_max_us, 0.0)
    if big > 0 and duration > 0:
        big = min(big, duration)
        if n == 2:
            gaps_us = [big]
        else:
            others = max(duration - big, 0.0)
            gaps_us = [others / (n - 2)] * (n - 1)
            gaps_us[n // 2] = big
    return [g / 1e6 for g in gaps_us]              # -> seconds


def render_flow_packets(row: dict, src: str, dst: str, sport: int, dport: int,
                        base_ts_us: int,
                        rng: Optional[random.Random] = None
                        ) -> list[PacketInfo]:
    """Synthesize the packet stream of one flow from its canonical features."""
    rng = rng or random.Random(0)

    n = max(1, min(int(_f(row, "fwd_packets")), 200))
    proto = int(_f(row, "protocol", 6))
    proto = proto if proto in (IPPROTO_TCP, IPPROTO_UDP) else proto or IPPROTO_TCP

    ip_hdr = 20
    transport_hdr = 20 if proto == IPPROTO_TCP else (8 if proto == IPPROTO_UDP else 0)
    header = ip_hdr + transport_hdr

    lengths = reconstruct_lengths(n, _f(row, "fwd_pkt_len_min"),
                                  _f(row, "fwd_pkt_len_max"),
                                  _f(row, "fwd_pkt_len_mean"))
    lengths.sort(reverse=True)          # data packets first, tail = acks/syns

    flags = _flags_for(n, int(_f(row, "syn_flag_count")),
                       int(_f(row, "ack_flag_count")),
                       int(_f(row, "psh_flag_count")),
                       int(_f(row, "fin_flag_count")),
                       int(_f(row, "rst_flag_count")),
                       int(_f(row, "urg_flag_count")))

    seg_mean = _f(row, "fwd_seg_size_avg")
    data_packets = max(0, min(int(_f(row, "act_data_pkt_fwd")), n))
    min_seg = _f(row, "min_seg_size_fwd")

    gaps = _gaps_for(n, _f(row, "duration_us"), _f(row, "fwd_iat_max"),
                     _f(row, "idle_max"))

    init_win = max(int(_f(row, "init_win_bytes_fwd", 8192)), 1)

    packets: list[PacketInfo] = []
    t_us = base_ts_us
    for i in range(n):
        payload = 0
        if i < data_packets:
            want = int(seg_mean) if seg_mean > 0 else max(lengths[i] - header, 0)
            if min_seg > 0:
                want = max(want, int(min_seg))
            payload = min(max(want, 0), 1400)
        total = header + payload

        packets.append(PacketInfo(
            ts_us=int(t_us), src=src, dst=dst, sport=sport, dport=dport,
            proto=proto, ip_total_len=total, ip_hdr_len=ip_hdr,
            transport_hdr_len=transport_hdr, payload_len=payload,
            tcp_flags=flags[i] if proto == IPPROTO_TCP else 0,
            tcp_win=init_win if proto == IPPROTO_TCP else 0,
        ))
        if i < n - 1:
            t_us += int(gaps[i] * 1_000_000)
    return packets
