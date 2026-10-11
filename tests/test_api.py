"""HTTP/WebSocket API against a real (pcap-replaying) pipeline."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, UDP, wrpcap

from src.config import (
    AlertPersistenceConfig,
    Config,
    ReplayConfig,
)
from src.server.app import create_app

BASE = 1735689600


def make_pcap(tmp_path):
    pkts = []
    for i in range(4):  # one TCP flow, 4 packets
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80,
                                                       flags=0x18)
        pkt.time = BASE + i
        pkts.append(pkt)
    udp = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=2000, dport=53)
    udp.time = BASE + 10
    pkts.append(udp)
    path = tmp_path / "cap.pcap"
    wrpcap(str(path), pkts)
    return path


def build_config(pcap, tmp_path):
    cfg = Config()
    cfg.capture.backend = "replay"
    cfg.capture.autostart = True
    cfg.capture.direction = "any"      # don't drop the synthetic 10.x traffic
    cfg.capture.replay = ReplayConfig(pcap_path=str(pcap), speed=0.0, loop=False)
    cfg.detection.model_path = str(tmp_path / "missing.joblib")
    cfg.alerts.persistence = AlertPersistenceConfig(
        enabled=True, path=str(tmp_path / "alerts.db"))
    return cfg


def wait_for(predicate, timeout=15.0, client=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def client(tmp_path):
    pcap = make_pcap(tmp_path)
    app = create_app(build_config(pcap, tmp_path))
    with TestClient(app) as c:
        yield c


def test_dashboard_page(client):
    html = client.get("/").text
    assert "UniThreat" in html
    assert client.get("/static/app.js").status_code == 200


def test_replay_autostart_produces_flows(client):
    ok = wait_for(lambda: client.get("/api/stats").json()["flows_total"] >= 2)
    assert ok, "replay pipeline did not finish in time"
    stats = client.get("/api/stats").json()
    assert stats["packets_total"] == 5
    assert stats["flows_total"] == 2          # 1 TCP flow + 1 UDP flow
    assert stats["running"] is False          # non-loop replay auto-finalised

    flows = client.get("/api/flows").json()["flows"]
    assert len(flows) == 2
    assert {f["proto_name"] for f in flows} == {"TCP", "UDP"}


def test_status_reflects_missing_model(client):
    # the replay pipeline finishes on its own (scapy import + 5 packets);
    # wait for it so the "running" check is not a race
    ok = wait_for(lambda: not client.get("/api/stats").json()["running"])
    assert ok
    status = client.get("/api/status").json()
    assert status["model"]["loaded"] is False
    assert status["capture"]["backend"] == "replay"
    assert status["capture"]["running"] is False


def test_config_endpoint(client):
    cfg = client.get("/api/config").json()
    assert cfg["flow"]["idle_timeout_s"] == 30.0
    assert cfg["capture"]["backend"] == "replay"
    assert cfg["detection"]["min_confidence"] == 0.55


def test_capture_start_stop_cycle(client):
    wait_for(lambda: not client.get("/api/stats").json()["running"])

    r = client.post("/api/capture/start")
    assert r.status_code == 200
    # the fresh pipeline replays the file again -> two more flows appear
    ok = wait_for(lambda: client.get("/api/stats").json()["flows_total"] >= 2)
    assert ok

    r = client.post("/api/capture/stop")
    assert r.status_code == 200
    ok = wait_for(lambda: not client.get("/api/stats").json()["running"])
    assert ok


def test_websocket_snapshot(client):
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert "status" in msg and "stats" in msg
        assert msg["status"]["capture"]["backend"] == "replay"
