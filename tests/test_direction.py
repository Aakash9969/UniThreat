"""Direction filter (unidirectional semantics)."""
from __future__ import annotations

import pytest

from src.capture.direction import DirectionFilter

from conftest import make_pkt


def test_outbound_mode():
    flt = DirectionFilter("outbound", trusted_cidrs=["192.168.10.0/24"])
    assert flt.allows(make_pkt(0, src="192.168.10.20", dst="8.8.8.8"))
    assert flt.allows(make_pkt(0, src="192.168.10.254", dst="8.8.8.8"))
    assert not flt.allows(make_pkt(0, src="8.8.8.8", dst="192.168.10.20"))


def test_inbound_mode():
    flt = DirectionFilter("inbound", monitored_hosts=["10.0.0.5"])
    assert flt.allows(make_pkt(0, src="1.2.3.4", dst="10.0.0.5"))
    assert not flt.allows(make_pkt(0, src="10.0.0.5", dst="1.2.3.4"))
    assert not flt.allows(make_pkt(0, src="1.2.3.4", dst="10.0.0.6"))


def test_any_mode():
    flt = DirectionFilter("any")
    assert flt.allows(make_pkt(0, src="1.1.1.1", dst="2.2.2.2"))


def test_invalid_mode():
    with pytest.raises(ValueError):
        DirectionFilter("sideways")


def test_bpf_builder():
    flt = DirectionFilter("outbound", trusted_cidrs=["192.168.10.0/24"])
    bpf = flt.build_bpf()
    assert bpf is not None and "src net 192.168.10.0/24" in bpf

    inbound = DirectionFilter("inbound", monitored_hosts=["10.0.0.5"])
    assert "dst host 10.0.0.5" in inbound.build_bpf()

    assert DirectionFilter("outbound").build_bpf() is None   # no nets configured
    assert DirectionFilter("any").build_bpf() is None
