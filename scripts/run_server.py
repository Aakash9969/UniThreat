#!/usr/bin/env python
"""Run the UniThreat detection server (dashboard + REST/WebSocket API).

Typical usage
-------------
  # live capture on a NIC (needs Npcap/libpcap; see config.yaml for direction)
  python scripts/run_server.py --interface eth0

  # offline demo: replay a pcap through the dashboard, looping forever
  python scripts/run_server.py --backend replay --pcap data/demo/demo_traffic.pcap

Options override config.yaml; the model comes from detection.model_path.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.config import ReplayConfig, load_config
from src.server.app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--backend", choices=["live", "replay"], default=None)
    parser.add_argument("--pcap", default=None, help="pcap path for --backend replay")
    parser.add_argument("--speed", type=float, default=None,
                        help="replay speed multiplier (0 = unlimited)")
    parser.add_argument("--no-loop", action="store_true",
                        help="stop after one replay pass instead of looping")
    parser.add_argument("--interface", default=None, help="capture interface name")
    parser.add_argument("--model", default=None, help="override model path")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-autostart", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)

    replay = config.capture.replay
    if args.pcap is not None:
        replay = replace(replay, pcap_path=args.pcap)
    if args.speed is not None:
        replay = replace(replay, speed=args.speed)
    if args.no_loop:
        replay = replace(replay, loop=False)
    capture = config.capture
    if args.backend:
        capture = replace(capture, backend=args.backend)
    if args.interface is not None:
        capture = replace(capture, interface=args.interface)
    capture = replace(capture, replay=replay)
    if args.no_autostart:
        capture = replace(capture, autostart=False)
    config = replace(config, capture=capture)

    if args.model:
        config = replace(config, detection=replace(
            config.detection, model_path=args.model))
    server = config.server
    if args.host:
        server = replace(server, host=args.host)
    if args.port is not None:
        server = replace(server, port=args.port)
    config = replace(config, server=server)

    app = create_app(config)

    import uvicorn
    model_note = config.detection.model_path
    backend_note = (f"replay {config.capture.replay.pcap_path}"
                   if config.capture.backend == "replay" else "live capture")
    print("=" * 62)
    print("  UniThreat — AI threat detection for unidirectional IP traffic")
    print("=" * 62)
    print(f"  dashboard : http://{server.host}:{server.port}")
    print(f"  API docs  : http://{server.host}:{server.port}/docs")
    print(f"  model     : {model_note}")
    print(f"  capture   : {backend_note} "
          f"(direction: {config.capture.direction})")
    print(f"  autostart : {config.capture.autostart}")
    print("=" * 62)

    uvicorn.run(app, host=server.host, port=server.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
