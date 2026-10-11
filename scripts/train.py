#!/usr/bin/env python
"""Train the threat-detection model on CIC-IDS2017.

Examples
--------
  # full dataset (needs ~2-4 GB RAM, RF training takes a few minutes)
  python scripts/train.py --data data/raw/cicids2017/traffic_labels

  # balanced subset for a fast workstation run
  python scripts/train.py --data data/raw/cicids2017/traffic_labels --cap 80000

Outputs (written to --out, default models/):
  latest_model.joblib      the detector bundle used by the server
  metrics.json             hold-out test metrics (full detail)
  feature_importances.json
  training_report.md       human-readable summary
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import load_config
from src.ml.train import train_model


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", required=True,
                        help="dataset directory / file / glob "
                             "(e.g. data/raw/cicids2017/traffic_labels)")
    parser.add_argument("--out", default="models/", help="output directory")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--cap", type=int, default=None,
                        help="max samples per class (default: config value)")
    parser.add_argument("--test-size", type=float, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--n-estimators", type=int, default=None)
    parser.add_argument("--no-xgboost", action="store_true",
                        help="train Random Forest only")
    parser.add_argument("--raw-features", action="store_true",
                        help="train on the raw CICFlowMeter CSV columns instead "
                             "of re-deriving features through the live extractor "
                             "(default: live features)")
    args = parser.parse_args()

    cfg = load_config(args.config).training
    overrides = {}
    if args.test_size is not None:
        overrides["test_size"] = args.test_size
    if args.seed is not None:
        overrides["random_state"] = args.seed
    if args.n_estimators is not None:
        overrides["n_estimators"] = args.n_estimators
    if overrides:
        cfg = replace(cfg, **overrides)

    result = train_model(
        data=args.data,
        out_dir=args.out,
        cfg=cfg,
        max_per_class=args.cap,
        use_xgboost=not args.no_xgboost,
        feature_mode="raw" if args.raw_features else "live",
    )

    print("\n================ TRAINING SUMMARY ================")
    print(f"model     : {result['model_name']}  ->  {result['model_path']}")
    m = result["metrics"]
    print(f"accuracy  : {m['accuracy']:.4f}")
    print(f"macro F1  : {m['macro_f1']:.4f}")
    td = m["threat_detection"]
    print(f"detection : precision={td['precision']:.4f} "
          f"recall={td['recall']:.4f} f1={td['f1']:.4f}")
    print(f"report    : {Path(result['out_dir']) / 'training_report.md'}")
    print("Next step: python scripts/run_server.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
