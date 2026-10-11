"""Shared pytest fixtures and path setup."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.capture.packet_info import PacketInfo  # noqa: E402
from src.config import FlowConfig  # noqa: E402


def make_pkt(ts_us, src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
             proto=6, total_len=100, ip_hdr=20, transport_hdr=20, payload=60,
             flags=0x10, win=8192) -> PacketInfo:
    return PacketInfo(
        ts_us=ts_us, src=src, dst=dst, sport=sport, dport=dport, proto=proto,
        ip_total_len=total_len, ip_hdr_len=ip_hdr,
        transport_hdr_len=transport_hdr, payload_len=payload,
        tcp_flags=flags if proto == 6 else 0, tcp_win=win if proto == 6 else 0,
    )


@pytest.fixture
def flow_cfg() -> FlowConfig:
    return FlowConfig(idle_timeout_s=30.0, active_timeout_s=120.0,
                      active_idle_threshold_s=5.0, max_concurrent_flows=1000)
