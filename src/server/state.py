"""Application state: wires config, detector, alerts, pipeline and events."""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import Optional

from src.alerts.manager import AlertManager
from src.alerts.store import SqliteAlertStore
from src.capture.direction import DirectionFilter
from src.capture.pipeline import CapturePipeline
from src.capture.source import build_source_from_config
from src.config import Config
from src.ml.detector import safe_load


def _primary_local_ip() -> Optional[str]:
    """Best-effort primary outbound IPv4 (UDP connect - no packets sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.connect(("192.0.2.1", 1))
            return s.getsockname()[0]
    except OSError:
        return None


def direction_mismatch_warnings(cfg, local_ip: Optional[str]) -> list[str]:
    """Warn when the one-way filter excludes this machine's own traffic.

    Roaming laptops change networks (new DHCP lease, different Wi-Fi) and a
    stale trusted_cidrs then silently drops every local packet - the dashboard
    shows nothing and gives no clue why. This turns that failure into an
    actionable on-screen warning.
    """
    warnings = []
    cap = cfg.capture
    if cap.direction != "outbound" or not cap.trusted_cidrs or not local_ip:
        return warnings
    try:
        addr = ipaddress.ip_address(local_ip)
    except ValueError:
        return warnings
    inside = any(addr in ipaddress.ip_network(c, strict=False)
                 for c in cap.trusted_cidrs)
    if not inside:
        warnings.append(
            f"this machine's IP {local_ip} is NOT inside "
            f"capture.trusted_cidrs {cap.trusted_cidrs} — all local outbound "
            "traffic is being filtered out, so the dashboard will look dead. "
            "Update trusted_cidrs in config.yaml to your current subnet "
            "(ipconfig shows your IP + mask), or run with --direction any."
        )
    return warnings


class AppState:
    def __init__(self, config: Config):
        self.config = config
        self.started_at = time.time()

        self.detector, self.model_error = safe_load(
            config.detection.model_path,
            min_confidence=config.detection.min_confidence,
        )

        store: Optional[SqliteAlertStore] = None
        if config.alerts.persistence.enabled:
            try:
                store = SqliteAlertStore(config.alerts.persistence.path)
            except Exception as exc:
                self.persistence_error = str(exc)
            else:
                self.persistence_error = None
        else:
            self.persistence_error = None

        self.alerts = AlertManager(
            dedup_window_s=config.alerts.dedup_window_s,
            max_recent=config.alerts.max_recent,
            store=store,
        )

        from src.server.event_hub import EventHub
        self.hub = EventHub()

        self._pipeline: Optional[CapturePipeline] = None
        self._pipeline_lock = threading.Lock()
        self._pipeline_error: Optional[str] = None
        self._capture_warnings: list[str] = self._direction_warnings()

    def _on_pipeline_event(self, event: dict) -> None:
        """Pipeline thread events -> status bookkeeping + dashboard fan-out."""
        if event.get("type") == "capture_error":
            self._pipeline_error = str(event.get("error", "capture failed"))
        self.hub.publish(event)

    # -- pipeline lifecycle ------------------------------------------------------

    def _direction_warnings(self) -> list[str]:
        """Fail-closed direction filters are silent packet eaters; warn loudly."""
        cap = self.config.capture
        warnings = []
        if cap.direction == "outbound" and not cap.trusted_cidrs:
            warnings.append(
                "capture.direction=outbound but trusted_cidrs is empty — every "
                "packet will be filtered out. Set capture.trusted_cidrs (e.g. "
                "your enclave's subnet) or use direction: any."
            )
        if cap.direction == "inbound" and not cap.monitored_hosts:
            warnings.append(
                "capture.direction=inbound but monitored_hosts is empty — every "
                "packet will be filtered out. Set capture.monitored_hosts or "
                "use direction: any."
            )
        warnings.extend(direction_mismatch_warnings(
            self.config, _primary_local_ip()))
        return warnings

    def build_pipeline(self) -> CapturePipeline:
        cfg = self.config
        source = build_source_from_config(cfg.capture)
        direction = DirectionFilter(
            mode=cfg.capture.direction,
            trusted_cidrs=cfg.capture.trusted_cidrs,
            monitored_hosts=cfg.capture.monitored_hosts,
        )
        return CapturePipeline(
            source=source,
            flow_cfg=cfg.flow,
            direction_filter=direction,
            detector=self.detector,
            alert_manager=self.alerts,
            on_event=self._on_pipeline_event,
            history_seconds=cfg.dashboard.history_points,
        )

    def start_capture(self) -> None:
        with self._pipeline_lock:
            if self._pipeline is not None and self._pipeline.is_running:
                return
            pipeline = self.build_pipeline()
            try:
                pipeline.start()
            except Exception as exc:
                self._pipeline_error = str(exc)
                raise
            self._pipeline = pipeline
            self._pipeline_error = None
            self._capture_warnings = self._direction_warnings()
            for warning in self._capture_warnings:
                print(f"[unithreat] WARNING: {warning}")

    def stop_capture(self) -> None:
        with self._pipeline_lock:
            pipeline = self._pipeline
        if pipeline is not None:
            pipeline.stop()
        with self._pipeline_lock:
            if self._pipeline is pipeline:
                self._pipeline = None

    @property
    def pipeline(self) -> Optional[CapturePipeline]:
        with self._pipeline_lock:
            return self._pipeline

    # -- introspection ---------------------------------------------------------------

    def status(self) -> dict:
        pipeline = self.pipeline
        running = bool(pipeline and pipeline.is_running)
        return {
            "app": "unithreat",
            "version": "0.1.0",
            "uptime_s": round(time.time() - self.started_at, 1),
            "capture": {
                "running": running,
                "error": self._pipeline_error,
                "warnings": self._capture_warnings,
                "backend": self.config.capture.backend,
                "direction": pipeline.direction_filter.describe() if pipeline else None,
                "source": pipeline.source.name if pipeline else None,
            },
            "model": {
                "loaded": self.detector is not None,
                "error": self.model_error,
                **(self.detector.info() if self.detector else {}),
            },
            "alerts": self.alerts.summary(),
            "persistence_error": self.persistence_error,
            "ws_clients": self.hub.n_clients,
        }

    def pipeline_stats(self) -> dict:
        pipeline = self.pipeline
        if pipeline is None:
            return {
                "running": False, "source": None, "direction": None,
                "started_at": None, "stopped_at": None,
                "packets_total": 0, "bytes_total": 0, "flows_total": 0,
                "flows_active": 0, "threats_total": 0, "completions_dropped": 0,
                "timeline": [], "flows_by_label": {},
            }
        return pipeline.snapshot_stats()

    def shutdown(self) -> None:
        try:
            self.stop_capture()
        finally:
            self.alerts.close()
