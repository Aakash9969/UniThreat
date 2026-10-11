"""FastAPI application: REST + WebSocket API and the live dashboard."""
from __future__ import annotations

import csv
import io
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse

from src.config import Config, load_config
from src.server.state import AppState

_STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(config: Optional[Config] = None) -> FastAPI:
    config = config or load_config("config.yaml")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state: AppState = app.state.state
        import asyncio
        state.hub.attach_loop(asyncio.get_running_loop())
        if config.capture.autostart:
            try:
                state.start_capture()
            except Exception:
                pass  # surfaced through /api/status capture.error
        try:
            yield
        finally:
            state.shutdown()

    app = FastAPI(
        title="UniThreat",
        description="AI-based detection of cyber threats in unidirectional IP traffic",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.state = AppState(config)

    # ------------------------------------------------------------------ helpers

    def state() -> AppState:
        return app.state.state  # type: ignore[return-value]

    # ------------------------------------------------------------------ pages

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(_STATIC_DIR / "index.html")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        path = _STATIC_DIR / "favicon.svg"
        if path.exists():
            return FileResponse(path, media_type="image/svg+xml")
        raise HTTPException(404)

    if _STATIC_DIR.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ------------------------------------------------------------------ REST API

    @app.get("/api/status")
    async def api_status():
        return state().status()

    @app.get("/health", include_in_schema=False)
    async def health():
        """Liveness probe for load balancers / Docker / systemd watchdogs."""
        s = state()
        running = bool(s.pipeline is not None and s.pipeline.is_running)
        return {
            "status": "ok",
            "capture_running": running,
            "model_loaded": s.detector is not None,
            "uptime_s": round(time.time() - s.started_at, 1),
        }

    @app.get("/api/stats")
    async def api_stats():
        return state().pipeline_stats()

    @app.get("/api/flows")
    async def api_flows(limit: int = Query(50, ge=1, le=500),
                       offset: int = Query(0, ge=0),
                       threats_only: bool = False):
        pipeline = state().pipeline
        flows = pipeline.recent_flows(limit=limit, offset=offset,
                                      only_threats=threats_only) if pipeline else []
        return {"flows": flows, "count": len(flows)}

    @app.get("/api/alerts")
    async def api_alerts(limit: int = Query(50, ge=1, le=500),
                         offset: int = Query(0, ge=0),
                         severity: Optional[str] = None,
                         label: Optional[str] = None):
        mgr = state().alerts
        store = mgr.store
        if store is not None:
            alerts = store.query(severity=severity, label=label,
                                 limit=limit, offset=offset)
            source = "sqlite"
        else:
            alerts = mgr.list_recent(limit=limit, offset=offset, severity=severity)
            source = "memory"
        return {
            "alerts": alerts,
            "count": len(alerts),
            "source": source,
            "summary": mgr.summary(),
        }

    @app.get("/api/alerts/export.csv")
    async def api_alerts_export():
        mgr = state().alerts
        store = mgr.store
        alerts = (store.query(limit=100_000) if store is not None
                  else mgr.list_recent(limit=100_000))
        buf = io.StringIO()
        if alerts:
            writer = csv.DictWriter(buf, fieldnames=list(alerts[0].keys()))
            writer.writeheader()
            writer.writerows(alerts)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )

    @app.get("/api/model")
    async def api_model():
        s = state()
        if s.detector is not None:
            return s.detector.info()
        return {"loaded": False, "error": s.model_error}

    @app.post("/api/capture/start")
    async def api_capture_start():
        s = state()
        if s.pipeline is not None and s.pipeline.is_running:
            raise HTTPException(409, "capture already running")
        try:
            s.start_capture()
        except Exception as exc:
            raise HTTPException(500, f"failed to start capture: {exc}")
        return {"ok": True, "status": s.status()}

    @app.post("/api/capture/stop")
    async def api_capture_stop():
        state().stop_capture()
        return {"ok": True}

    @app.get("/api/config")
    async def api_config():
        c = config
        return {
            "capture": {
                "backend": c.capture.backend,
                "interface": c.capture.interface,
                "direction": c.capture.direction,
                "trusted_cidrs": c.capture.trusted_cidrs,
                "monitored_hosts": c.capture.monitored_hosts,
                "bpf_filter": c.capture.bpf_filter,
                "replay": {
                    "pcap_path": c.capture.replay.pcap_path,
                    "speed": c.capture.replay.speed,
                    "loop": c.capture.replay.loop,
                },
            },
            "flow": {
                "idle_timeout_s": c.flow.idle_timeout_s,
                "active_timeout_s": c.flow.active_timeout_s,
                "active_idle_threshold_s": c.flow.active_idle_threshold_s,
                "max_concurrent_flows": c.flow.max_concurrent_flows,
            },
            "detection": {
                "model_path": c.detection.model_path,
                "min_confidence": c.detection.min_confidence,
            },
            "alerts": {
                "dedup_window_s": c.alerts.dedup_window_s,
                "persistence": {
                    "enabled": c.alerts.persistence.enabled,
                    "path": c.alerts.persistence.path,
                },
            },
        }

    # ------------------------------------------------------------------ WebSocket

    @app.websocket("/ws")
    async def ws_endpoint(websocket: WebSocket):
        await websocket.accept()
        s = state()
        queue = s.hub.subscribe()
        try:
            snapshot = {
                "type": "snapshot",
                "status": s.status(),
                "stats": s.pipeline_stats(),
                "alerts": s.alerts.list_recent(limit=50),
                "flows": (s.pipeline.recent_flows(limit=50) if s.pipeline else []),
            }
            await websocket.send_json(snapshot)
            while True:
                event = await queue.get()
                await websocket.send_json(event)
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            s.hub.unsubscribe(queue)

    return app
