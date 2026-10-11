"""End-to-end training + detection on a tiny synthetic dataset."""
from __future__ import annotations

import pandas as pd
import pytest

from src.config import TrainingConfig
from src.features.schema import CANONICAL_FEATURES
from src.ml.detector import DetectionResult, ThreatDetector, safe_load
from src.ml.train import train_model


def _row(**overrides) -> dict:
    row = {name: 0.0 for name in CANONICAL_FEATURES}
    row.update(overrides)
    return row


def make_dataset(tmp_path, n=120):
    """Two well-separated classes: BENIGN vs PortScan-like traffic."""
    benign_rows = [
        _row(protocol=6, duration_us=2_000_000, fwd_packets=12,
             fwd_bytes=9000, fwd_pkt_len_mean=750.0, fwd_iat_mean=180_000.0,
             fwd_seg_size_avg=700.0, ack_flag_count=10, psh_flag_count=4)
        for _ in range(n)
    ]
    scan_rows = [
        _row(protocol=6, duration_us=0, fwd_packets=1, fwd_bytes=44,
             fwd_pkt_len_mean=44.0, fwd_iat_mean=0.0, fwd_seg_size_avg=0.0,
             syn_flag_count=1)
        for _ in range(n)
    ]
    rows = benign_rows + scan_rows
    df = pd.DataFrame(rows)
    df["label"] = [label for label in ([ "BENIGN" ] * n + ["PortScan"] * n)]
    path = tmp_path / "synthetic.csv"
    df.to_csv(path, index=False)
    return path, benign_rows[0], scan_rows[0]


def test_train_and_detect_roundtrip(tmp_path):
    csv_path, benign_row, scan_row = make_dataset(tmp_path)
    out_dir = tmp_path / "models"

    result = train_model(
        data=csv_path,
        out_dir=out_dir,
        cfg=TrainingConfig(test_size=0.25, random_state=42,
                           n_estimators=15, use_xgboost=False),
        feature_mode="raw",       # probes below use the raw row features
        verbose=False,
    )
    assert result["metrics"]["accuracy"] > 0.95
    assert (out_dir / "latest_model.joblib").exists()
    assert (out_dir / "metrics.json").exists()
    assert (out_dir / "training_report.md").exists()

    detector = ThreatDetector.load(out_dir / "latest_model.joblib")
    assert "PortScan" in detector.classes

    benign = detector.detect(benign_row)
    assert benign.label == "BENIGN"
    assert not benign.is_threat
    assert benign.confidence >= detector.min_confidence

    scan = detector.detect(scan_row)
    assert scan.label == "PortScan"
    assert scan.is_threat
    assert scan.severity == "low"          # PortScan -> low severity
    assert scan.category == "reconnaissance"
    assert isinstance(scan, DetectionResult)
    d = scan.to_dict()
    assert d["label"] == "PortScan" and d["is_threat"] is True


def test_missing_features_are_imputed(tmp_path):
    csv_path, benign_row, _ = make_dataset(tmp_path)
    out_dir = tmp_path / "m"
    train_model(data=csv_path, out_dir=out_dir,
                cfg=TrainingConfig(test_size=0.25, random_state=7,
                                   n_estimators=10, use_xgboost=False),
                feature_mode="raw",
                verbose=False)
    detector = ThreatDetector.load(out_dir / "latest_model.joblib", min_confidence=0.5)

    partial = {k: v for k, v in list(benign_row.items())[:5]}   # most features gone
    verdict = detector.detect(partial)
    assert verdict.label in ("BENIGN", "PortScan")   # must not raise
    assert 0.0 <= verdict.confidence <= 1.0


def test_low_confidence_not_flagged_as_threat(tmp_path):
    csv_path, benign_row, scan_row = make_dataset(tmp_path)
    out_dir = tmp_path / "m2"
    train_model(data=csv_path, out_dir=out_dir,
                cfg=TrainingConfig(test_size=0.25, random_state=7,
                                   n_estimators=10, use_xgboost=False),
                feature_mode="raw",
                verbose=False)
    detector = ThreatDetector.load(out_dir / "latest_model.joblib",
                                    min_confidence=0.99)
    scan = detector.detect(scan_row)
    if scan.confidence < 0.99:
        assert not scan.is_threat and scan.low_confidence
    else:
        assert scan.is_threat


def test_safe_load_missing_model(tmp_path):
    detector, error = safe_load(tmp_path / "nope.joblib")
    assert detector is None and error and "train" in error.lower()


def test_live_feature_mode_roundtrip(tmp_path):
    """Live-mode training: detect flows rendered through the live extractor."""
    import random

    from src.features.flow_features import FlowAccumulator
    from src.synthesis.render import render_flow_packets

    csv_path, benign_row, scan_row = make_dataset(tmp_path)
    out_dir = tmp_path / "live"
    result = train_model(
        data=csv_path, out_dir=out_dir,
        cfg=TrainingConfig(test_size=0.25, random_state=7,
                           n_estimators=15, use_xgboost=False),
        feature_mode="live", verbose=False,
    )
    assert result["metadata"]["feature_mode"] == "live"
    detector = ThreatDetector.load(out_dir / "latest_model.joblib")

    def live_features(row, seed):
        packets = render_flow_packets(
            row, "10.0.0.1", "10.0.0.2", 1234, 80,
            base_ts_us=1_000_000, rng=random.Random(seed))
        acc = FlowAccumulator(("10.0.0.1", 1234, "10.0.0.2", 80, 6))
        for pkt in packets:
            acc.add(pkt)
        return acc.finish("final").features

    assert detector.detect(live_features(benign_row, 1)).label == "BENIGN"
    scan = detector.detect(live_features(scan_row, 2))
    assert scan.label == "PortScan" and scan.is_threat
