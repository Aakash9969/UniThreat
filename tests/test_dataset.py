"""Dataset loading: messy CIC-IDS2017 variants -> canonical schema."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src.dataset.cicids2017 import (
    DatasetError,
    canonicalize,
    clean_features,
    load_dataset,
)
from src.features.schema import (
    BENIGN,
    CANONICAL_FEATURES,
    normalize_label,
)

# Original MachineLearningCVE / TrafficLabelling-style names, deliberately
# inconsistent (leading spaces, dashes, duplicated column, "Tot" vs "Total").
MESSY_COLUMNS = {
    "protocol":              " Protocol",
    "duration_us":           " Flow Duration",
    "fwd_packets":           "Total Fwd Packet",
    "fwd_bytes":             " Total Length of Fwd Packets",
    "fwd_pkt_len_max":       "Fwd Packet Length Max",
    "fwd_pkt_len_min":       " Fwd Packet Length Min",
    "fwd_pkt_len_mean":      "Fwd Packet Length Mean",
    "fwd_pkt_len_std":       "Fwd Packet Length Std",
    "flow_bytes_per_s":      "Flow Bytes/s",
    "flow_packets_per_s":    " Flow Packets/s",
    "flow_iat_mean":         "Flow IAT Mean",
    "flow_iat_std":          " Flow IAT Std",
    "flow_iat_max":          "Flow IAT Max",
    "flow_iat_min":          " Flow IAT Min",
    "fwd_iat_tot":           "Fwd IAT Tot",           # CVE variant name
    "fwd_iat_mean":          " Fwd IAT Mean",
    "fwd_iat_std":           "Fwd IAT Std",
    "fwd_iat_max":           " Fwd IAT Max",
    "fwd_iat_min":           "Fwd IAT Min",
    "fwd_psh_flags":         " Fwd PSH Flags",
    "fwd_urg_flags":         "Fwd URG Flags",
    "fwd_header_bytes":      " Fwd Header Length.1",   # duplicated column
    "fwd_packets_per_s":     "Fwd Packets/s",
    "fin_flag_count":        " FIN Flag Count",
    "syn_flag_count":        "SYN Flag Count",
    "rst_flag_count":        " RST Flag Count",
    "psh_flag_count":       "PSH Flag Count",
    "ack_flag_count":        " ACK Flag Count",
    "urg_flag_count":       "URG Flag Count",
    "cwr_flag_count":        "CWE Flag Count",         # CICFlowMeter's "CWE"
    "ece_flag_count":        " ECE Flag Count",
    "fwd_seg_size_avg":      "Avg Fwd Segment Size",   # TrafficLabelling name
    "init_win_bytes_fwd":    " Init_Win_bytes_forward",
    "act_data_pkt_fwd":      "act_data_pkt_fwd",
    "min_seg_size_fwd":      " min_seg_size_forward",
    "active_mean":           "Active Mean",
    "active_std":            " Active Std",
    "active_max":            "Active Max",
    "active_min":            " Active Min",
    "idle_mean":             "Idle Mean",
    "idle_std":              " Idle Std",
    "idle_max":              "Idle Max",
    "idle_min":              " Idle Min",
}


def make_messy_csv(tmp_path, rows: list[dict], label=" Label"):
    """rows: list of {canonical_name: value, 'label': raw_label}."""
    frame = {}
    for canonical, messy in MESSY_COLUMNS.items():
        frame[messy] = [r.get(canonical, 0) for r in rows]
    frame[label] = [r["label"] for r in rows]
    df = pd.DataFrame(frame)
    path = tmp_path / "part.csv"
    df.to_csv(path, index=False)
    return path


def test_canonicalize_handles_messy_variants(tmp_path):
    rows = [
        {"label": "BENIGN", "duration_us": 1000, "fwd_packets": 3},
        {"label": "Web Attack \u2013 Brute Force", "duration_us": 2000,
         "fwd_packets": 5, "flow_bytes_per_s": float("inf")},
        {"label": "DoS slowloris", "duration_us": 3000, "fwd_packets": 7},
    ]
    path = make_messy_csv(tmp_path, rows)
    df = canonicalize(pd.read_csv(path), origin=str(path))

    assert list(df.columns[:-1]) == CANONICAL_FEATURES
    assert df["label"].tolist() == [BENIGN, "Web Attack - Brute Force",
                                    "DoS slowloris"]
    # numeric coercion worked despite odd column names
    assert df["duration_us"].tolist() == [1000, 2000, 3000]


def test_clean_features_replaces_inf(tmp_path):
    rows = [{"label": BENIGN, "flow_bytes_per_s": float("inf"),
             "flow_packets_per_s": float("-inf")}]
    path = make_messy_csv(tmp_path, rows)
    df = canonicalize(pd.read_csv(path), origin=str(path))
    cleaned = clean_features(df)
    assert not np.isinf(cleaned.to_numpy()).any()
    assert cleaned["flow_bytes_per_s"].isna().all()


def test_label_normalisation():
    assert normalize_label("BENIGN") == BENIGN
    assert normalize_label("  benign ") == BENIGN
    assert normalize_label("DDoS") == "DDoS"
    assert normalize_label("PortScan") == "PortScan"
    assert normalize_label("Web Attack \u2013 XSS") == "Web Attack - XSS"
    assert normalize_label("Web Attack - Sql Injection") == "Web Attack - SQL Injection"
    assert normalize_label("DoS Slowhttptest") == "DoS Slowhttptest"
    assert normalize_label("FTP-Patator") == "FTP-Patator"
    assert normalize_label("Heartbleed") == "Heartbleed"
    assert normalize_label("weird new attack") == "weird new attack"


def test_unlabeled_rows_are_dropped(tmp_path):
    """Mirrors can carry rows with missing labels — never a 'nan' class."""
    df = pd.DataFrame({
        "Flow Duration": [10, 20, 30, 40],
        **{c: [1] * 4 for c in MESSY_COLUMNS.values()},
        " Label": ["BENIGN", None, "DDoS", "nan"],
    })
    out = canonicalize(df, origin="mirror.parquet")
    assert out["label"].tolist() == ["BENIGN", "DDoS"]
    assert "nan" not in set(out["label"])


def test_missing_feature_raises(tmp_path):
    df = pd.DataFrame({"Flow Duration": [1], "Total Fwd Packets": [1],
                       " Label": [BENIGN]})
    with pytest.raises(DatasetError):
        canonicalize(df, origin="incomplete.csv")


def test_load_dataset_with_per_class_cap(tmp_path):
    rows = []
    for _ in range(10):
        rows.append({"label": BENIGN, "fwd_packets": 1})
    for _ in range(4):
        rows.append({"label": "DDoS", "fwd_packets": 50})
    path = make_messy_csv(tmp_path, rows)
    df = load_dataset(path, max_per_class=3, verbose=False)
    counts = df["label"].value_counts().to_dict()
    assert counts == {BENIGN: 3, "DDoS": 3}
    assert list(df.columns[:-1]) == CANONICAL_FEATURES
