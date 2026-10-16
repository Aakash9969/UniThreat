"""Stale-network detection: warn when the machine's IP leaves trusted_cidrs."""
from __future__ import annotations

from src.config import CaptureConfig, Config
from src.server.state import direction_mismatch_warnings


def _cfg(direction: str, cidrs: list[str]) -> Config:
    cfg = Config()
    cfg.capture = CaptureConfig(direction=direction, trusted_cidrs=cidrs)
    return cfg


def test_warns_when_local_ip_outside_trusted_cidrs():
    ws = direction_mismatch_warnings(
        _cfg("outbound", ["192.168.10.0/24"]), "10.202.65.193")
    assert len(ws) == 1
    assert "10.202.65.193" in ws[0]
    assert "trusted_cidrs" in ws[0]


def test_no_warning_when_inside():
    assert direction_mismatch_warnings(
        _cfg("outbound", ["10.202.64.0/20"]), "10.202.65.193") == []


def test_no_warning_for_any_direction_or_empty_cidrs():
    assert direction_mismatch_warnings(
        _cfg("any", ["192.168.10.0/24"]), "10.202.65.193") == []
    assert direction_mismatch_warnings(
        _cfg("outbound", []), "10.202.65.193") == []


def test_no_warning_for_invalid_ip():
    assert direction_mismatch_warnings(
        _cfg("outbound", ["192.168.10.0/24"]), "not-an-ip") == []
    assert direction_mismatch_warnings(
        _cfg("outbound", ["192.168.10.0/24"]), None) == []
