"""Alert manager: dedup, severity stats, SQLite persistence."""
from __future__ import annotations

import time

from src.alerts.manager import AlertManager
from src.alerts.store import SqliteAlertStore
from src.ml.detector import DetectionResult


def flow_record(src="10.0.0.1", dst="10.0.0.2", sport=1000, dport=80,
                proto_name="TCP", duration_us=1234):
    return {"src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto_name": proto_name, "duration_us": duration_us}


def detection(label="PortScan", confidence=0.9):
    return DetectionResult(
        label=label, confidence=confidence, top=[(label, confidence)],
        is_threat=True, low_confidence=False,
        severity="low" if label == "PortScan" else "high",
        category="reconnaissance" if label == "PortScan" else "dos",
    )


def test_dedup_merges_repeated_threats():
    mgr = AlertManager(dedup_window_s=60)
    rec = flow_record()
    a1, created1 = mgr.add(rec, detection())
    a2, created2 = mgr.add(rec, detection(confidence=0.95))
    assert created1 and not created2
    assert a2["id"] == a1["id"]
    assert a2["occurrences"] == 2
    assert a2["confidence"] == 0.95          # keeps the strongest confidence
    assert mgr.total_created == 1


def test_dedup_expires_after_window():
    mgr = AlertManager(dedup_window_s=0.05)
    rec = flow_record()
    mgr.add(rec, detection())
    time.sleep(0.08)
    _, created = mgr.add(rec, detection())
    assert created                             # window elapsed -> new alert


def test_different_endpoints_new_alerts():
    mgr = AlertManager()
    mgr.add(flow_record(src="10.0.0.1"), detection())
    mgr.add(flow_record(src="10.0.0.2"), detection())
    mgr.add(flow_record(src="10.0.0.1", dport=443), detection())
    assert mgr.total_created == 3
    assert mgr.summary()["by_label"] == {"PortScan": 3}


def test_severity_summary():
    mgr = AlertManager()
    mgr.add(flow_record(), detection(label="PortScan"))       # low
    mgr.add(flow_record(src="10.0.0.9"), detection(label="DDoS",
                                                   confidence=0.8))  # high? -> mapped
    summary = mgr.summary()
    assert summary["total_created"] == 2
    assert summary["by_severity"]["low"] == 1
    assert "high" in summary["by_severity"] or "critical" in summary["by_severity"]


def test_sqlite_persistence(tmp_path):
    store = SqliteAlertStore(tmp_path / "alerts.db")
    mgr = AlertManager(store=store)

    rec = flow_record()
    mgr.add(rec, detection())
    mgr.add(rec, detection())                    # dedup -> upsert occurrences=2
    mgr.add(flow_record(src="10.0.0.7"),
            detection(label="DDoS", confidence=0.7))

    # the writer thread flushes batches ~every 0.5s
    deadline = time.time() + 3.0
    while store.count() < 2 and time.time() < deadline:
        time.sleep(0.05)

    assert store.count() == 2
    rows = store.query(limit=10)
    by_label = {r["label"]: r for r in rows}
    assert by_label["PortScan"]["occurrences"] == 2
    assert by_label["DDoS"]["src"] == "10.0.0.7"

    stats = store.stats()
    assert stats["total"] == 2
    assert stats["by_label"]["PortScan"] == 1   # one alert, occurrences merged

    store.close()
    # reopening still sees history
    store2 = SqliteAlertStore(tmp_path / "alerts.db")
    assert store2.count() == 2
    store2.close()


def test_list_recent_filtering():
    mgr = AlertManager(max_recent=100)
    for i in range(20):
        mgr.add(flow_record(src=f"10.0.0.{i}"), detection())
    recent = mgr.list_recent(limit=5)
    assert len(recent) == 5
    assert recent[0]["src"] == "10.0.0.19"       # newest first
    low_only = mgr.list_recent(severity="high")
    assert low_only == []
