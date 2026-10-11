"""Flow synthesis: dataset rows -> packets -> live features."""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.features.flow_features import FlowAccumulator
from src.features.schema import CANONICAL_FEATURES
from src.synthesis.render import render_flow_packets


def _row(**over) -> dict:
    row = {name: 0.0 for name in CANONICAL_FEATURES}
    row.update(over)
    return row


def _accumulate(row, rng_seed=1):
    import random
    packets = render_flow_packets(row, "10.0.0.1", "10.0.0.2", 1234, 80,
                                  base_ts_us=1_000_000,
                                  rng=random.Random(rng_seed))
    acc = FlowAccumulator(("10.0.0.1", 1234, "10.0.0.2", 80, 6))
    for pkt in packets:
        acc.add(pkt)
    return packets, acc.finish("final").features


def test_single_packet_flow_render():
    row = _row(fwd_packets=1, init_win_bytes_fwd=1024, syn_flag_count=1,
               protocol=6)
    packets, feats = _accumulate(row)
    assert len(packets) == 1
    assert feats["fwd_packets"] == 1
    assert feats["init_win_bytes_fwd"] == 1024
    assert feats["syn_flag_count"] == 1
    assert packets[0].ip_total_len >= 40      # physically valid


def test_counts_flags_and_window_survive():
    row = _row(fwd_packets=7, protocol=6,
               syn_flag_count=1, ack_flag_count=7, psh_flag_count=4,
               init_win_bytes_fwd=29200,
               duration_us=3_000_000,
               fwd_pkt_len_min=40, fwd_pkt_len_max=1400, fwd_pkt_len_mean=400)
    packets, feats = _accumulate(row)
    assert len(packets) == 7
    assert feats["fwd_packets"] == 7
    assert feats["syn_flag_count"] == 1
    assert feats["ack_flag_count"] == 7
    assert feats["psh_flag_count"] == 4
    assert feats["init_win_bytes_fwd"] == 29200
    assert feats["duration_us"] == 3_000_000


def test_lengths_honour_min_max():
    row = _row(fwd_packets=10, fwd_pkt_len_min=60, fwd_pkt_len_max=1500,
               fwd_pkt_len_mean=200)
    packets, _ = _accumulate(row)
    lens = [p.ip_total_len for p in packets]
    assert min(lens) >= 60 - 20       # header clamping may lift tiny values
    assert max(lens) <= 1500
    assert 40 <= max(lens)


def test_idle_gap_reproduces_slowloris_shape():
    row = _row(fwd_packets=4, duration_us=100_000_000,
               idle_max=25_000_000, init_win_bytes_fwd=29200)
    _, feats = _accumulate(row)
    assert feats["duration_us"] == 100_000_000
    assert feats["idle_max"] > 20_000_000
    assert feats["idle_mean"] > 0


def test_zero_packet_rows_get_one_packet():
    packets = render_flow_packets(_row(fwd_packets=0), "a", "b", 1, 2, 0)
    assert len(packets) == 1


def test_live_features_frame_end_to_end():
    from src.ml.train import live_features_frame

    df = pd.DataFrame([_row(fwd_packets=2, syn_flag_count=1,
                             init_win_bytes_fwd=1024, label_x=1)
                        for _ in range(6)])
    df.columns = list(CANONICAL_FEATURES) + ["label_x"]
    df = df.rename(columns={"label_x": "label"})
    df["label"] = ["PortScan"] * 3 + ["BENIGN"] * 3
    df.loc[df["label"] == "BENIGN", "init_win_bytes_fwd"] = 8192

    live = live_features_frame(df, verbose=False)
    assert list(live.columns[:-1]) == list(CANONICAL_FEATURES)
    assert len(live) == 6
    # features are now sensor semantics: finite, no NaN
    assert np.isfinite(live[CANONICAL_FEATURES].to_numpy()).all()
    scan = live[live["label"] == "PortScan"]
    assert (scan["init_win_bytes_fwd"] == 1024).all()
    assert (scan["syn_flag_count"] == 1).all()
