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

from bootstrap import anchor_project_root
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

    # work from any directory: relative paths (config.yaml, models/, data/)
    # resolve against the project root
    root = anchor_project_root()

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

    # fail fast with an actionable message when live capture can't work here
    if config.capture.backend == "live":
        import platform
        try:
            import scapy.all  # noqa: F401  (loads the arch layer)
            from scapy.config import conf
            if platform.system() == "Windows" and not conf.use_pcap:
                print("!" * 62)
                print("  WARNING: no packet driver found (Npcap is missing).")
                print("  Live capture will NOT receive packets on Windows")
                print("  until you install Npcap: https://npcap.com")
                print("  (enable 'WinPcap API-compatible Mode' during setup)")
                print("  For a no-NIC demo, run instead:")
                print("    python scripts/run_server.py --backend replay "
                      "--pcap data/demo/demo_traffic.pcap")
                print("!" * 62)
        except ImportError:
            pass

    # fail fast (and clearly) when the port is already taken — otherwise
    # uvicorn dies with a cryptic [Errno 10048] bind error
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((server.host, server.port))
        except OSError:
            print(f"ERROR: port {server.port} on {server.host} is already in use.")
            print("An earlier UniThreat instance is probably still running.")
            print("  - stop it: press Ctrl+C in its terminal window, or")
            print("  - kill it:  Get-NetTCPConnection -LocalPort "
                  f"{server.port} -State Listen | %{{ Stop-Process -Id $_.OwningProcess -Force }}")
            print(f"  - or use another port:  python scripts/run_server.py --port {server.port + 1}")
            return 1

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
