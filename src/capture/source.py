"""Packet sources: live Scapy sniffing and PCAP replay.

All sources share one contract:

    source.name                  -> human-readable description
    source.provides_wall_clock   -> True if packet timestamps follow wall time
    source.run(sink, stop_event, on_finished)   -> blocking; run in a thread

``sink(PacketInfo)`` is called for every IPv4 packet; ``on_finished()`` fires
exactly once when the source is exhausted (replay) — live captures simply
never finish.
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from src.capture.packet_info import PacketInfo

Sink = Callable[[PacketInfo], None]


class BaseSource:
    name: str = "source"
    provides_wall_clock: bool = True

    def run(self, sink: Sink, stop_event: threading.Event,
            on_finished: Optional[Callable[[], None]] = None) -> None:
        raise NotImplementedError

    def stop(self) -> None:  # optional fast-stop hook
        pass


def _ensure_scapy_layers() -> None:
    """Import the full Scapy layer registry.

    Scapy maps pcap linktypes (Ethernet=1, raw-IP=228/101, ...) to dissection
    classes lazily via ``conf.l2types`` when the layer modules are imported.
    Importing only ``scapy.utils`` leaves that registry empty, so PcapReader
    silently falls back to raw bytes and every packet would be dropped.
    """
    import scapy.all  # noqa: F401  (registers all layers + linktypes)


class ScapyLiveSource(BaseSource):
    """Live capture via Scapy's AsyncSniffer (requires Npcap/WinPcap/libpcap)."""

    def __init__(self, interface: Optional[str] = None,
                 bpf: str = "ip", promiscuous: bool = True):
        self.interface = interface
        self.bpf = bpf
        self.promiscuous = promiscuous
        self._sniffer = None
        self._stop_event = threading.Event()
        self.name = f"live capture (iface={interface or 'default'}, bpf={bpf!r})"

    def _on_packet(self, pkt, sink: Sink) -> None:
        if self._stop_event.is_set():
            return
        try:
            info = PacketInfo.from_scapy(pkt)
        except Exception:  # malformed packet — never kill the capture thread
            return
        if info is not None:
            sink(info)

    def run(self, sink: Sink, stop_event: threading.Event,
            on_finished: Optional[Callable[[], None]] = None) -> None:
        from scapy.sendrecv import AsyncSniffer

        _ensure_scapy_layers()

        self._stop_event = stop_event
        self._sniffer = AsyncSniffer(
            iface=self.interface, filter=self.bpf, store=False,
            prn=lambda p: self._on_packet(p, sink),
        )
        try:
            self._sniffer.start()
        except Exception as exc:
            raise RuntimeError(self._failure_hint(exc)) from exc

        # AsyncSniffer failures (no Npcap/libpcap, bad interface, ...) happen
        # inside its own thread and are stored on `.exception` — poll for
        # them so a dead capture surfaces as a capture_error instead of
        # "running" forever with zero packets.
        if not self._wait_until_alive(timeout=3.0):
            self._raise_sniffer_error()
        while not stop_event.wait(timeout=0.25):
            exc = getattr(self._sniffer, "exception", None)
            if exc is not None:
                self._raise_sniffer_error()
        try:
            self._sniffer.stop(stop=True)
        except Exception:
            pass

    def _wait_until_alive(self, timeout: float) -> bool:
        """True once the sniffer is provably receiving (continue_sniff set)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if getattr(self._sniffer, "exception", None) is not None:
                return False
            if getattr(self._sniffer, "continue_sniff", False):
                return True
            thread = getattr(self._sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                return False
            time.sleep(0.1)
        # no exception, no proof of life, thread still spinning — treat as
        # alive (some platforms start slowly)
        return True

    def _raise_sniffer_error(self) -> None:
        exc = getattr(self._sniffer, "exception", None)
        try:
            self._sniffer.stop(stop=True)
        except Exception:
            pass
        raise RuntimeError(self._failure_hint(exc))

    @staticmethod
    def _failure_hint(exc: Optional[BaseException]) -> str:
        base = f"live capture failed: {exc}. " if exc else "live capture failed. "
        return base + (
            "On Windows install Npcap (https://npcap.com, enable the "
            "'Install Npcap in WinPcap API-compatible Mode' option); on Linux "
            "verify the interface name and CAP_NET_RAW privileges. For a "
            "no-NIC demo run: python scripts/run_server.py --backend replay "
            "--pcap data/demo/demo_traffic.pcap"
        )

    def stop(self) -> None:
        self._stop_event.set()


class PcapReplaySource(BaseSource):
    """Replays a pcap file through the pipeline (offline analysis / demos).

    Packet timestamps come from the capture, so the flow-expiry clock is
    virtual and a 10x-speed replay still produces identical flow boundaries.
    """

    provides_wall_clock = False

    def __init__(self, path: str, speed: float = 0.0, loop: bool = False):
        self.path = path
        self.speed = max(0.0, speed)
        self.loop = loop
        self.name = f"replay ({path}, speed={speed or 'max'})"

    def run(self, sink: Sink, stop_event: threading.Event,
            on_finished: Optional[Callable[[], None]] = None) -> None:
        from scapy.utils import PcapReader

        _ensure_scapy_layers()

        while not stop_event.is_set():
            prev_ts: Optional[float] = None
            with PcapReader(self.path) as reader:
                for pkt in reader:
                    if stop_event.is_set():
                        break
                    info = PacketInfo.from_scapy(pkt)
                    if info is None:
                        continue
                    if self.speed > 0:
                        if prev_ts is not None:
                            delay = (info.ts_us / 1e6) - prev_ts
                            if delay > 0:
                                time.sleep(min(delay / self.speed, 1.0))
                        prev_ts = info.ts_us / 1e6
                    sink(info)
            if not self.loop or stop_event.is_set():
                break
        if on_finished is not None and not stop_event.is_set():
            on_finished()


def build_source_from_config(capture_cfg) -> BaseSource:
    """Factory used by the server/scripts (config-driven)."""
    if capture_cfg.backend == "replay":
        if not capture_cfg.replay.pcap_path:
            raise ValueError("capture.backend='replay' requires capture.replay.pcap_path")
        return PcapReplaySource(capture_cfg.replay.pcap_path,
                                 speed=capture_cfg.replay.speed,
                                 loop=capture_cfg.replay.loop)
    bpf = capture_cfg.bpf_filter or "ip"
    return ScapyLiveSource(interface=capture_cfg.interface, bpf=bpf,
                           promiscuous=capture_cfg.promiscuous)
