"""Configuration loading (YAML over dataclass defaults)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


# --------------------------------------------------------------------------
# Dataclasses (defaults live here; config.yaml overrides them)
# --------------------------------------------------------------------------

@dataclass
class ReplayConfig:
    pcap_path: Optional[str] = None
    speed: float = 1.0
    loop: bool = True


@dataclass
class CaptureConfig:
    backend: str = "live"            # live | replay
    autostart: bool = True
    interface: Optional[str] = None
    promiscuous: bool = True
    bpf_filter: Optional[str] = None
    direction: str = "outbound"      # outbound | inbound | any
    trusted_cidrs: list[str] = field(default_factory=list)
    monitored_hosts: list[str] = field(default_factory=list)
    replay: ReplayConfig = field(default_factory=ReplayConfig)


@dataclass
class FlowConfig:
    idle_timeout_s: float = 30.0
    active_timeout_s: float = 120.0
    active_idle_threshold_s: float = 5.0
    max_concurrent_flows: int = 100_000


@dataclass
class DetectionConfig:
    model_path: str = "models/latest_model.joblib"
    min_confidence: float = 0.55


@dataclass
class AlertPersistenceConfig:
    enabled: bool = True
    path: str = "data/alerts/alerts.db"


@dataclass
class AlertsConfig:
    dedup_window_s: float = 60.0
    max_recent: int = 2000
    persistence: AlertPersistenceConfig = field(default_factory=AlertPersistenceConfig)


@dataclass
class TrainingConfig:
    test_size: float = 0.2
    random_state: int = 42
    n_estimators: int = 200
    use_xgboost: bool = True
    max_samples_per_class: int = 0


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8000


@dataclass
class DashboardConfig:
    history_points: int = 120


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    flow: FlowConfig = field(default_factory=FlowConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)


# --------------------------------------------------------------------------
# Loading / merging
# --------------------------------------------------------------------------

_SECTION_TYPES = {
    "server": ServerConfig,
    "capture": CaptureConfig,
    "flow": FlowConfig,
    "detection": DetectionConfig,
    "alerts": AlertsConfig,
    "training": TrainingConfig,
    "dashboard": DashboardConfig,
}

_SUBSECTIONS = {"replay": (CaptureConfig, "replay", ReplayConfig),
                "persistence": (AlertsConfig, "persistence", AlertPersistenceConfig)}


def _coerce(cls: type, data: dict[str, Any]) -> Any:
    """Build a dataclass instance from a dict, keeping defaults for absent keys."""
    if not isinstance(data, dict):
        raise ValueError(f"expected mapping for {cls.__name__}, got {type(data).__name__}")
    known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"unknown option(s) in [{cls.__name__}]: {sorted(unknown)}")
    return cls(**data)


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration.

    ``path`` may be a file, a directory containing ``config.yaml``, or None
    (then only the built-in defaults are used). Missing keys always fall back
    to the defaults defined in the dataclasses above.
    """
    cfg = Config()
    if path is None:
        return cfg

    p = Path(path)
    if p.is_dir():
        p = p / "config.yaml"
    if not p.exists():
        return cfg

    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}

    for section, cls in _SECTION_TYPES.items():
        if section in raw:
            data = dict(raw[section] or {})
            # nested subsections
            for sub_key, (parent_cls, parent_field, sub_cls) in _SUBSECTIONS.items():
                if parent_cls is cls and sub_key in data:
                    data[sub_key] = _coerce(sub_cls, data.pop(sub_key) or {})
            setattr(cfg, section, _coerce(cls, data))

    unknown_sections = set(raw) - set(_SECTION_TYPES)
    if unknown_sections:
        raise ValueError(f"unknown config section(s): {sorted(unknown_sections)}")
    return cfg
