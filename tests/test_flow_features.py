"""FlowAccumulator: exact statistics for deterministic packet streams."""
from __future__ import annotations

from src.features.flow_features import (ACK, FIN, PSH, SYN, FlowAccumulator)

from conftest import make_pkt

US = 1_000_000


def key(pkt):
    return (pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto)


def test_single_packet_flow(flow_cfg):
    acc = FlowAccumulator(key(make_pkt(1_000)), idle_us_threshold=5 * US)
    acc.add(make_pkt(1_000, total_len=120, ip_hdr=20, transport_hdr=20, payload=80))
    cf = acc.finish("final")
    f = cf.features
    assert f["fwd_packets"] == 1
    assert f["fwd_bytes"] == 120
    assert f["duration_us"] == 0
    assert f["flow_bytes_per_s"] == 0.0      # zero-duration -> 0, not inf
    assert f["flow_packets_per_s"] == 0.0
    assert f["fwd_iat_mean"] == 0.0 and f["fwd_iat_tot"] == 0.0
    assert f["active_mean"] == 0.0
    assert f["idle_mean"] == 0.0
    assert f["init_win_bytes_fwd"] == 8192
    assert f["fwd_header_bytes"] == 40
    assert cf.n_packets == 1 and cf.n_bytes == 120


def test_three_packets_no_idle(flow_cfg):
    acc = FlowAccumulator(("a", 1, "b", 2, 6), idle_us_threshold=5 * US)
    for ts, length in [(0, 100), (1 * US, 200), (3 * US, 300)]:
        acc.add(make_pkt(ts, total_len=length, payload=length - 40))
    f = acc.finish("idle_timeout").features

    assert f["fwd_packets"] == 3
    assert f["fwd_bytes"] == 600
    assert f["duration_us"] == 3 * US
    assert f["flow_packets_per_s"] == 1.0            # 3 packets / 3 s
    assert abs(f["flow_bytes_per_s"] - 200.0) < 1e-6  # 600 B / 3 s
    # IATs: 1s, 2s -> mean 1.5s, pop-std 0.5s, max 2s, min 1s
    assert f["fwd_iat_mean"] == 1.5 * US
    assert abs(f["fwd_iat_std"] - 0.5 * US) < 1.0
    assert f["fwd_iat_max"] == 2 * US
    assert f["fwd_iat_min"] == 1 * US
    assert f["fwd_iat_tot"] == 3 * US
    # one continuous active period of 3s, no idle
    assert f["active_mean"] == 3 * US and f["active_std"] == 0.0
    assert f["active_max"] == 3 * US and f["active_min"] == 3 * US
    assert f["idle_mean"] == 0.0 and f["idle_max"] == 0.0
    # packet length stats
    assert f["fwd_pkt_len_max"] == 300
    assert f["fwd_pkt_len_min"] == 100
    assert f["fwd_pkt_len_mean"] == 200.0


def test_packet_length_std(flow_cfg):
    import math
    acc = FlowAccumulator(("a", 1, "b", 2, 6), idle_us_threshold=5 * US)
    for ts, length in [(0, 100), (1 * US, 200), (3 * US, 300)]:
        acc.add(make_pkt(ts, total_len=length, payload=length - 40))
    f = acc.finish("idle_timeout").features
    # population std of {100,200,300} = 66.666...
    assert abs(f["fwd_pkt_len_std"] - math.sqrt(20000.0 / 3)) < 1e-6


def test_idle_gap_split(flow_cfg):
    acc = FlowAccumulator(("a", 1, "b", 2, 6), idle_us_threshold=5 * US)
    acc.add(make_pkt(0))
    acc.add(make_pkt(6 * US))    # 6s gap > 5s threshold
    f = acc.finish("final").features
    assert f["fwd_iat_mean"] == 6 * US
    assert f["idle_mean"] == 6 * US
    assert f["idle_max"] == 6 * US
    assert f["active_mean"] == 0.0   # two zero-length active periods


def test_multiple_idle_gaps(flow_cfg):
    acc = FlowAccumulator(("a", 1, "b", 2, 6), idle_us_threshold=5 * US)
    for ts in [0, 1 * US, 10 * US, 12 * US, 30 * US]:
        acc.add(make_pkt(ts))
    f = acc.finish("final").features
    # idle gaps: 9s (1->10), 18s (12->30); active bursts: 0-1s, 10-12s,
    # plus a zero-length trailing burst opened by the final packet at 30s
    # (a packet that follows an idle gap starts a fresh, instant burst).
    assert f["idle_mean"] == 13.5 * US
    assert f["idle_max"] == 18 * US
    assert f["idle_min"] == 9 * US
    assert f["active_mean"] == 1 * US            # mean of {1s, 2s, 0s}
    assert f["active_max"] == 2 * US
    assert f["active_min"] == 0 * US


def test_tcp_flag_counts(flow_cfg):
    acc = FlowAccumulator(("a", 1, "b", 2, 6), idle_us_threshold=5 * US)
    acc.add(make_pkt(0, flags=SYN | ACK, win=1024))
    acc.add(make_pkt(US, flags=PSH | ACK))
    acc.add(make_pkt(2 * US, flags=FIN))
    f = acc.finish("final").features
    assert f["syn_flag_count"] == 1
    assert f["ack_flag_count"] == 2
    assert f["psh_flag_count"] == 1
    assert f["fin_flag_count"] == 1
    assert f["fwd_psh_flags"] == 1
    assert f["fwd_urg_flags"] == 0
    assert f["init_win_bytes_fwd"] == 1024


def test_payload_segment_stats(flow_cfg):
    acc = FlowAccumulator(("a", 1, "b", 2, 6), idle_us_threshold=5 * US)
    acc.add(make_pkt(0, total_len=120, payload=100))
    acc.add(make_pkt(US, total_len=340, payload=300))
    acc.add(make_pkt(2 * US, total_len=40, payload=0))  # pure ACK
    f = acc.finish("final").features
    assert f["act_data_pkt_fwd"] == 2
    assert f["fwd_seg_size_avg"] == 200.0
    assert f["min_seg_size_fwd"] == 100


def test_udp_flow_has_no_tcp_fields(flow_cfg):
    acc = FlowAccumulator(("a", 1, "b", 2, 17), idle_us_threshold=5 * US)
    acc.add(make_pkt(0, proto=17, transport_hdr=8, payload=32, total_len=60))
    f = acc.finish("final").features
    assert f["protocol"] == 17
    assert f["syn_flag_count"] == 0
    assert f["init_win_bytes_fwd"] == 0
    assert f["fwd_header_bytes"] == 28
    assert f["fwd_seg_size_avg"] == 32.0


def test_schema_covers_all_features():
    from src.features.schema import CANONICAL_FEATURES
    acc = FlowAccumulator(("a", 1, "b", 2, 6))
    f = acc.finish("final").features
    assert set(f) == set(CANONICAL_FEATURES)
    assert len(f) == 43
