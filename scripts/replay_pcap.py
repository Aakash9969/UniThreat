#!/usr/bin/env python
"""Offline pcap analysis: run a capture through the pipeline, print a report.

No server needed — useful for batch triage of recorded one-way traffic and for
verifying a trained model against a specific pcap.

  python scripts/replay_pcap.py --pcap data/demo/demo_traffic.pcap
  python scripts/replay_pcap.py --pcap capture.pcap --json report.json
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import anchor_project_root
from src.alerts.manager import AlertManager
from src.capture.direction import DirectionFilter
from src.capture.pipeline import CapturePipeline
from src.capture.source import PcapReplaySource
from src.config import load_config
from src.ml.detector import safe_load


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True, help="pcap file to analyse")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--speed", type=float, default=0.0,
                        help="replay speed multiplier (default 0 = as fast as possible)")
    parser.add_argument("--json", default=None, help="write full report JSON here")
    parser.add_argument("--csv", default=None, help="write flow records CSV here")
    parser.add_argument("--top", type=int, default=15, help="rows in the report tables")
    args = parser.parse_args()

    anchor_project_root()   # relative paths (config.yaml, models/) -> repo root

    if not Path(args.pcap).exists():
        print(f"pcap not found: {args.pcap}", file=sys.stderr)
        return 2

    config = load_config(args.config)
    detector, model_error = safe_load(
        config.detection.model_path,
        min_confidence=config.detection.min_confidence)
    if detector is None:
        print(f"[warn] {model_error} — flows will be reported without verdicts.\n")

    alerts = AlertManager(dedup_window_s=config.alerts.dedup_window_s,
                          max_recent=100_000)
    pipeline = CapturePipeline(
        source=PcapReplaySource(args.pcap, speed=args.speed, loop=False),
        flow_cfg=config.flow,
        direction_filter=DirectionFilter("any"),
        detector=detector,
        alert_manager=alerts,
        on_event=None,
        recent_flow_capacity=1_000_000,
        history_seconds=config.dashboard.history_points,
    )

    print(f"Analysing {args.pcap} ...")
    t0 = time.perf_counter()
    pipeline.start()
    while pipeline.is_running:
        time.sleep(0.25)
    pipeline.stop()
    elapsed = time.perf_counter() - t0

    stats = pipeline.snapshot_stats()
    flows = pipeline.recent_flows(limit=1_000_000)
    threat_flows = [f for f in flows if f["verdict"] and f["verdict"]["is_threat"]]
    all_alerts = alerts.list_recent(limit=100_000)

    # ---------------------------------------------------------------- report
    print("\n" + "=" * 62)
    print("  UniThreat — offline pcap analysis")
    print("=" * 62)
    print(f"packets          : {stats['packets_total']:,}")
    print(f"flows analysed   : {stats['flows_total']:,} "
          f"({elapsed:.1f}s wall time)")
    print(f"threats detected : {stats['threats_total']:,}")

    by_label = sorted(stats["flows_by_label"].items(), key=lambda kv: -kv[1])
    print("\nverdict distribution:")
    for label, count in by_label[:args.top]:
        pct = 100 * count / max(stats["flows_total"], 1)
        print(f"  {label:<32} {count:>10,}  ({pct:5.2f}%)")

    print("\ntop alerts:")
    if all_alerts:
        ordered = sorted(all_alerts, key=lambda a: -a["occurrences"])
        for a in ordered[:args.top]:
            print(f"  [{a['severity']:<8}] {a['label']:<24} "
                  f"{a['src']}:{a['sport']} -> {a['dst']}:{a['dport']}  "
                  f"x{a['occurrences']}")
    else:
        print("  (none)")

    report = {
        "pcap": args.pcap,
        "stats": stats,
        "alerts": all_alerts,
        "flows": flows,
        "model_error": model_error,
    }
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nJSON report -> {args.json}")
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=list(flows[0].keys()) if flows else ["id"])
            writer.writeheader()
            writer.writerows(flows)
        print(f"flow CSV     -> {args.csv}")

    return 0 if detector is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
