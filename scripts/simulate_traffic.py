#!/usr/bin/env python
"""Generate demo unidirectional traffic: benign background + attack episodes.

Two modes:

  pcap (default)  writes a .pcap you can replay through the dashboard:
      python scripts/simulate_traffic.py
      python scripts/run_server.py --backend replay --pcap data/demo/demo_traffic.pcap

  send           emits the packets live on a NIC (loopback or a real
                  interface; needs Npcap/WinPcap/libpcap):
      python scripts/simulate_traffic.py --send --iface "Ethernet"

The traffic models what a sensor sees on the *sending* side of a data diode:
client -> server packets only, no responses.

Attack episodes reproduce the *empirical fingerprints* of the corresponding
CIC-IDS2017 classes (measured medians: initial TCP windows, per-flow packet
counts, payload sizes, pacing), so the trained model actually fires on them:

  t=8s    PortScan    nmap-style: 1-packet SYN flows, win=1024, 1024 ports
  t=26s   DDoS        LOIC-style: 3 tiny (~20B) packets per flow, win=8192
  t=44s   DoS Hulk    3-packet flows with ~339B HTTP GETs, win=29200
  t=60s   DoS slowloris  partial headers every 12-25s over ~100s, win=29200
  t=80s   exfiltration  steady 1400B upload (realistic benign for this model)
  t=110s  SSH brute force  12 auth attempts per flow, small PSH, win=29200

Benign background (Windows-like, win=8192): web conversations + DNS.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bootstrap import anchor_project_root

EPOCH = 1735689600  # fixed base timestamp for reproducible pcaps

# TCP flag bitmasks (Scapy values)
S, A, FA, PA, R, RA = 0x02, 0x10, 0x11, 0x18, 0x04, 0x14

WIN_WINDOWS = 8192     # benign web/DNS + LOIC signature
WIN_NMAP = 1024        # nmap SYN scan signature
WIN_LINUX = 29200       # CIC-IDS2017 Linux attack hosts (Hulk/slowloris/patator)


def build_schedule(duration: float, rng: random.Random) -> list[tuple[float, object]]:
    """Returns [(offset_s, scapy_packet)] sorted by time."""
    from scapy.all import Ether, IP, TCP, UDP, Raw

    events: list[tuple[float, object]] = []
    MAC_SRC = "aa:bb:cc:00:10:20"
    MAC_DST = "aa:bb:cc:00:00:05"

    def tcp(src, sport, dst, dport, flags, payload=b"", win=WIN_WINDOWS):
        pkt = (Ether(src=MAC_SRC, dst=MAC_DST)
               / IP(src=src, dst=dst)
               / TCP(sport=sport, dport=dport, flags=flags, window=win))
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def udp(src, sport, dst, dport, payload=b""):
        return (Ether(src=MAC_SRC, dst=MAC_DST)
                / IP(src=src, dst=dst)
                / UDP(sport=sport, dport=dport)
                / Raw(load=payload))

    # ---- benign background: web conversations (win=8192, Windows-like) ------
    t = 0.0
    while t < duration:
        conv_len = rng.randint(3, 9)
        sport = rng.randint(32768, 61000)
        dport = rng.choice([80, 443, 8080])
        convo = [S]
        for _ in range(conv_len):
            convo.append(PA if rng.random() < 0.75 else A)
        convo.append(FA)
        for i, flags in enumerate(convo):
            payload = bytes(rng.getrandbits(8) for _ in range(
                rng.randint(60, 1200))) if flags == PA else b""
            events.append((t + i * rng.uniform(0.15, 0.5),
                           tcp("192.168.10.20", sport, "93.184.216.34",
                               dport, flags, payload)))
        t += rng.uniform(0.6, 2.2)

    # ---- benign background: DNS lookups ---------------------------------------
    t = 0.5
    while t < duration:
        events.append((t, udp(
            "192.168.10.20", rng.randint(32768, 61000), "8.8.8.8", 53,
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06example\x03com\x00")))
        t += rng.uniform(1.5, 4.0)

    # ---- episode 1: PortScan — nmap SYN sweep, win=1024 (t=8s) -----------------
    t = 8.0
    for port in range(1, 1025):
        events.append((t, tcp("192.168.10.66", 40000, "10.0.0.5", port, S,
                              win=WIN_NMAP)))
        t += 0.001

    # ---- episode 2: DDoS — LOIC-style tiny packets, win=8192 (t=26s) -----------
    t = 26.0
    while t < 36.0:
        sport = rng.randint(1024, 65535)
        for i in range(3):  # 3-packet flow, ~20B payloads, ~200ms apart
            events.append((t + i * 0.2,
                           tcp("192.168.10.99", sport, "10.0.0.5", 80, PA,
                               b"hi mom? *", win=WIN_WINDOWS)))
        t += 0.02

    # ---- episode 3: DoS Hulk — 3-packet flows, ~339B GETs, win=29200 (t=44s) ---
    t = 44.0
    get = (b"GET /?q=" + b"a" * 300 + b" HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n")
    while t < 54.0:
        sport = rng.randint(1024, 65535)
        events.append((t, tcp("192.168.10.77", sport, "10.0.0.5", 80, S,
                             win=WIN_LINUX)))
        events.append((t + 0.024, tcp("192.168.10.77", sport, "10.0.0.5", 80,
                                      PA, get, win=WIN_LINUX)))
        events.append((t + 0.048, tcp("192.168.10.77", sport, "10.0.0.5", 80,
                                      PA, b"", win=WIN_LINUX)))
        t += 0.03

    # ---- episode 4: DoS slowloris — partial headers, long idle (t=60s) -------
    # EACH flow goes quiet for 12-25s between probes (above the 5s active/idle
    # threshold, below the 30s flow idle timeout), reproducing the ~19s
    # idle_mean / ~100s duration signature of the real attack. Aggregate
    # traffic across the 25 flows is a steady ~1.4 pkt/s drip.
    t_end = min(duration, 158.0)
    slow_ports = [rng.randint(1024, 65535) for _ in range(25)]
    next_t = {sport: 60.0 + i * 0.3 for i, sport in enumerate(slow_ports)}
    started: set[int] = set()
    while next_t:
        sport, t = min(next_t.items(), key=lambda kv: kv[1])
        if t > t_end:
            next_t.pop(sport)
            continue
        if sport not in started:
            started.add(sport)
            events.append((t, tcp("192.168.10.88", sport, "10.0.0.5", 80, S,
                                 win=WIN_LINUX)))
            next_t[sport] = t + 0.1
        else:
            events.append((t, tcp("192.168.10.88", sport, "10.0.0.5", 80, PA,
                                  b"GET / HTTP/1.1\r\nHost: x\r\nX-a: ",
                                  win=WIN_LINUX)))
            next_t[sport] = t + rng.uniform(12.0, 25.0)

    # ---- episode 5: bulk exfiltration (t=80s) — realistic benign --------------
    t = 80.0
    while t < 95.0:
        events.append((t, tcp("192.168.10.20", 52000, "45.33.10.7", 8443, PA,
                             bytes(rng.getrandbits(8) for _ in range(1400)))))
        t += 0.005

    # ---- episode 6: SSH brute force — patator-style (t=110s) -----------------
    t = 110.0
    while t < 130.0:
        sport = rng.randint(1024, 65535)
        events.append((t, tcp("192.168.10.66", sport, "10.0.0.5", 22, S,
                             win=WIN_LINUX)))
        for i in range(12):  # 12 auth attempts, small PSH packets
            events.append((t + 0.05 + i * 0.25,
                           tcp("192.168.10.66", sport, "10.0.0.5", 22, PA,
                               b"SSH-2.0-OpenSSH_7.4\r\n", win=WIN_LINUX)))
        events.append((t + 0.05 + 12 * 0.25,
                       tcp("192.168.10.66", sport, "10.0.0.5", 22, RA,
                           win=WIN_LINUX)))
        t += 1.5

    events.sort(key=lambda ev: ev[0])
    return [(off, pkt) for off, pkt in events if off < duration]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="data/demo/demo_traffic.pcap",
                        help="output pcap path (pcap mode)")
    parser.add_argument("--duration", type=float, default=160.0,
                        help="virtual seconds of traffic to generate (default 160)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--send", action="store_true",
                        help="send packets live instead of writing a pcap")
    parser.add_argument("--iface", default=None,
                        help="interface for --send (default: Scapy's choice)")
    parser.add_argument("--loop", action="store_true",
                        help="--send mode: repeat the schedule forever")
    args = parser.parse_args()

    anchor_project_root()   # relative paths (data/demo) -> repo root

    rng = random.Random(args.seed)
    print(f"building {args.duration:.0f}s schedule (seed {args.seed}) ...")
    events = build_schedule(args.duration, rng)
    print(f"  {len(events):,} packets generated")

    from scapy.all import wrpcap
    from scapy.utils import EDecimal

    for off, pkt in events:
        pkt.time = EDecimal(EPOCH + off)

    if not args.send:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(out), [pkt for _, pkt in events])
        print(f"\nwritten: {out}")
        print("replay it through the dashboard with:")
        print(f"  python scripts/run_server.py --backend replay --pcap {out}")
        return 0

    # -- live send mode ----------------------------------------------------------
    from scapy.sendrecv import sendp
    print(f"\nsending {len(events):,} packets on "
          f"{args.iface or 'default interface'} (Ctrl+C to stop)")
    while True:
        base = time.monotonic()
        for off, pkt in events:
            wait = off - (time.monotonic() - base)
            if wait > 0:
                time.sleep(wait)
            sendp(pkt, iface=args.iface, verbose=False)
        if not args.loop:
            break
        print("schedule complete; looping ...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
