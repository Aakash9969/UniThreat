#!/usr/bin/env python
"""Render real CIC-IDS2017 flows into a replayable pcap (demo generation).

Each sampled dataset row is converted into a packet sequence via
``src.synthesis.render`` — the same renderer the trainer uses in "live
features" mode — so the pcap exercises exactly the traffic the model was
trained on. Replayed through the dashboard, the sensor reconstructs the
flows and the model fires on the attack episodes.

Usage:
  python scripts/render_flows.py                 # writes data/demo/demo_traffic.pcap
  python scripts/render_flows.py --verify        # + offline detection check
  python scripts/render_flows.py --n-per-class 40 --duration 240
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import anchor_project_root

EPOCH = 1735689600
MAC_SRC, MAC_DST = "aa:bb:cc:00:10:20", "aa:bb:cc:00:00:05"

DEFAULT_CLASSES = [
    "PortScan", "DDoS", "DoS Hulk", "DoS slowloris", "DoS Slowhttptest",
    "DoS GoldenEye", "SSH-Patator", "FTP-Patator", "Bot",
    "Web Attack - Brute Force", "Infiltration", "Heartbleed",
]

# flow label -> (episode start fraction, episode span fraction)
EPISODES = {
    "PortScan": (0.10, 0.12),
    "DDoS": (0.26, 0.08),
    "DoS Hulk": (0.38, 0.08),
    "DoS GoldenEye": (0.49, 0.05),
    "DoS slowloris": (0.56, 0.38),
    "DoS Slowhttptest": (0.60, 0.28),
    "SSH-Patator": (0.72, 0.08),
    "FTP-Patator": (0.81, 0.05),
    "Bot": (0.88, 0.05),
    "Web Attack - Brute Force": (0.91, 0.05),
    "Infiltration": (0.95, 0.03),
    "Heartbleed": (0.97, 0.02),
}


def find_dataset_dir() -> Path:
    for candidate in (
        Path("data/raw/cicids2017/traffic_labels"),
        Path("data/raw/cicids2017/machine_learning"),
    ):
        if candidate.is_dir() and list(candidate.glob("*.parquet")):
            return candidate
    raise SystemExit("dataset not found — run scripts/download_data.py first")


def load_class_samples(data_dir: Path, classes: list[str], n_per_class: int,
                       rng: random.Random) -> dict[str, list[dict]]:
    import pandas as pd
    from src.dataset.cicids2017 import TARGET_COLUMN, canonicalize

    wanted = set(classes) | {"BENIGN"}
    samples: dict[str, list[dict]] = {c: [] for c in wanted}
    seen_keys: set[tuple] = set()

    for path in sorted(data_dir.glob("*.parquet")):
        df = pd.read_parquet(path)
        df = df[df["Label"].notna()]
        label_norm = df["Label"].astype(str).str.strip().str.lower()
        for cls in wanted:
            key = "benign" if cls == "BENIGN" else cls.lower()
            sub = df[label_norm == key]
            need = n_per_class * (4 if cls == "BENIGN" else 1)
            if len(sub) > need:
                sub = sub.sample(n=need, random_state=rng.randint(0, 2**31))
            if sub.empty:
                continue
            canon = canonicalize(sub.copy(), origin=str(path))
            for _, row in canon.iterrows():
                rec = row.to_dict()
                signature = tuple(round(float(rec.get(k, 0) or 0), 3) for k in
                                 ("fwd_packets", "fwd_bytes", "duration_us",
                                  "init_win_bytes_fwd"))
                dedup = (cls, signature)
                if dedup in seen_keys:
                    continue
                seen_keys.add(dedup)
                samples[cls].append(rec)
    return samples


def build_pcap_events(samples: dict[str, list[dict]], duration: float,
                      n_per_class: int, rng: random.Random):
    """Lay rendered flows onto a demo timeline; returns [(t, scapy_pkt)]."""
    from scapy.all import Ether, IP, TCP, UDP, Raw

    from src.synthesis.render import render_flow_packets

    events: list[tuple[float, object]] = []

    def flow_packets_to_events(row, src_ip, dst_ip, sport, dport, base_s):
        for pkt in render_flow_packets(row, src_ip, dst_ip, sport, dport,
                                       base_ts_us=int((EPOCH + base_s) * 1e6),
                                       rng=rng):
            if pkt.proto == 17:
                wire = (Ether(src=MAC_SRC, dst=MAC_DST)
                        / IP(src=pkt.src, dst=pkt.dst)
                        / UDP(sport=pkt.sport, dport=pkt.dport))
            else:
                wire = (Ether(src=MAC_SRC, dst=MAC_DST)
                        / IP(src=pkt.src, dst=pkt.dst)
                        / TCP(sport=pkt.sport, dport=pkt.dport,
                              flags=pkt.tcp_flags, window=pkt.tcp_win))
            if pkt.payload_len:
                wire = wire / Raw(load=bytes(rng.getrandbits(8)
                                             for _ in range(pkt.payload_len)))
            wire.time = pkt.ts_us / 1e6        # scapy pkt.time is in seconds
            events.append((pkt.ts_us / 1e6 - EPOCH, wire))

    # ---- benign background spread over the whole timeline --------------------
    benign = samples.get("BENIGN", [])
    for i, row in enumerate(benign):
        base = duration * (i / max(len(benign), 1)) + rng.uniform(0, 2)
        flow_packets_to_events(row, "192.168.10.20", "93.184.216.34",
                               rng.randint(32768, 61000), 443, base)

    # ---- attack episodes --------------------------------------------------------
    for cls, flows in samples.items():
        if cls == "BENIGN" or not flows:
            continue
        start_frac, span_frac = EPISODES.get(cls, (0.5, 0.1))
        t0 = duration * start_frac
        span = duration * span_frac
        batch = flows[:n_per_class]
        for i, row in enumerate(batch):
            base = t0 + span * (i / max(len(batch), 1))
            flow_packets_to_events(row, "192.168.10.50", "192.168.10.5",
                                   rng.randint(1024, 65535), 80, base)

    events.sort(key=lambda ev: ev[0])
    return [(t, pkt) for t, pkt in events if t < duration]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="data/demo/demo_traffic.pcap")
    parser.add_argument("--data", default=None, help="dataset dir (default: auto)")
    parser.add_argument("--n-per-class", type=int, default=60)
    parser.add_argument("--duration", type=float, default=220.0,
                        help="virtual seconds of the demo timeline")
    parser.add_argument("--seed", type=int, default=11)
    parser.add_argument("--verify", action="store_true",
                        help="after rendering, run the pipeline offline and "
                             "report detection results")
    args = parser.parse_args()

    anchor_project_root()   # relative paths (config.yaml, models/) -> repo root

    data_dir = Path(args.data) if args.data else find_dataset_dir()
    rng = random.Random(args.seed)

    print(f"loading samples from {data_dir} ...")
    samples = load_class_samples(data_dir, DEFAULT_CLASSES,
                                 args.n_per_class, rng)
    print(f"  {sum(len(v) for v in samples.values())} flows sampled:")
    for cls, flows in samples.items():
        if flows:
            print(f"    {cls:<24} {len(flows):>4}")

    events = build_pcap_events(samples, args.duration, args.n_per_class, rng)
    print(f"rendered {len(events):,} packets over {args.duration:.0f}s")

    from scapy.all import wrpcap
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), [pkt for _, pkt in events])
    print(f"written: {out}")
    print(f"replay it: python scripts/run_server.py --backend replay --pcap {out}")

    if args.verify:
        print("\nverifying through the live pipeline ...")
        from src.alerts.manager import AlertManager
        from src.capture.direction import DirectionFilter
        from src.capture.pipeline import CapturePipeline
        from src.capture.source import PcapReplaySource
        from src.config import load_config
        from src.ml.detector import safe_load
        cfg = load_config("config.yaml")
        det, err = safe_load(cfg.detection.model_path,
                             cfg.detection.min_confidence)
        if det is None:
            print(f"  model missing: {err}")
            return 1
        pipeline = CapturePipeline(
            source=PcapReplaySource(str(out), speed=0.0, loop=False),
            flow_cfg=cfg.flow, direction_filter=DirectionFilter("any"),
            detector=det, alert_manager=AlertManager(max_recent=100_000),
            recent_flow_capacity=1_000_000)
        pipeline.start()
        t0 = time.perf_counter()
        while pipeline.is_running:
            time.sleep(0.2)
        pipeline.stop()
        stats = pipeline.snapshot_stats()
        print(f"  analysed {stats['flows_total']:,} flows "
              f"in {time.perf_counter()-t0:.0f}s -> "
              f"{stats['threats_total']:,} threats")
        for label, count in sorted(stats["flows_by_label"].items(),
                                   key=lambda kv: -kv[1]):
            print(f"    {label:<26} {count:>6,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
