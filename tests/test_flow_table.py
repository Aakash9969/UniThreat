"""FlowTable: idle/active expiry, epoch invalidation, memory guard."""
from __future__ import annotations

from src.capture.flow_table import FlowTable

from conftest import make_pkt

US = 1_000_000


def test_idle_timeout(flow_cfg):
    table = FlowTable(flow_cfg)
    table.update(make_pkt(0))
    table.update(make_pkt(10 * US))
    assert table.n_active == 1
    # 15s after the last packet: not yet expired (idle timeout is 30s)
    assert table.poll_expired(25 * US) == []
    # 31s after the last packet: expires
    finished = table.poll_expired(45 * US)
    assert len(finished) == 1
    assert finished[0].reason == "idle_timeout"
    assert finished[0].n_packets == 2
    assert table.n_active == 0


def test_active_timeout_beats_idle_for_long_flows(flow_cfg):
    table = FlowTable(flow_cfg)
    # a flow that keeps sending one packet every second for 121s
    for i in range(121):
        table.update(make_pkt(i * US))
    finished = table.poll_expired(121 * US + 1)
    assert len(finished) == 1
    assert finished[0].reason == "active_timeout"
    assert finished[0].n_packets == 121
    assert table.n_active == 0


def test_flow_recreation_after_expiry(flow_cfg):
    table = FlowTable(flow_cfg)
    table.update(make_pkt(0))
    finished = table.poll_expired(31 * US)
    assert len(finished) == 1

    # same 5-tuple later => a brand-new flow
    table.update(make_pkt(60 * US))
    assert table.n_active == 1
    finished = table.poll_expired(100 * US)
    assert len(finished) == 1
    assert finished[0].first_ts == 60 * US


def test_independent_flows(flow_cfg):
    table = FlowTable(flow_cfg)
    table.update(make_pkt(0, src="10.0.0.1"))
    table.update(make_pkt(0, src="10.0.0.9"))          # different flow key
    table.update(make_pkt(5 * US, src="10.0.0.1"))
    assert table.n_active == 2
    finished = table.poll_expired(40 * US)
    assert len(finished) == 2
    assert {cf.key[0] for cf in finished} == {"10.0.0.1", "10.0.0.9"}


def test_unidirectional_no_reverse_merge(flow_cfg):
    """Reverse-direction packets are a separate flow (diode semantics)."""
    table = FlowTable(flow_cfg)
    fwd = make_pkt(0, src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=80)
    bwd = make_pkt(US, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1000)
    table.update(fwd)
    table.update(bwd)
    assert table.n_active == 2


def test_flush_all(flow_cfg):
    table = FlowTable(flow_cfg)
    table.update(make_pkt(0, src="10.0.0.1"))
    table.update(make_pkt(1, src="10.0.0.2"))
    finished = table.flush_all("final")
    assert len(finished) == 2
    assert all(cf.reason == "final" for cf in finished)
    assert table.n_active == 0


def test_max_concurrent_flows_eviction(flow_cfg):
    cfg = flow_cfg
    cfg.max_concurrent_flows = 3
    table = FlowTable(cfg)
    # 4 distinct flows; the most idle one gets evicted when the 4th arrives
    table.update(make_pkt(0, src="10.0.0.1"))
    table.update(make_pkt(US, src="10.0.0.2"))
    table.update(make_pkt(2 * US, src="10.0.0.3"))
    table.update(make_pkt(3 * US, src="10.0.0.4"))
    # overflow completion is staged and drained by the next poll
    finished = table.poll_expired(4 * US)
    reasons = [cf.reason for cf in finished]
    assert "overflow" in reasons
    assert table.n_active <= 3
