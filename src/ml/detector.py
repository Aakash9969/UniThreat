"""Live threat detection: canonical features -> ML verdict."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

import joblib
import numpy as np

from src.features.schema import (
    BENIGN,
    category_for,
    is_threat_label,
    severity_for,
)


class ModelNotLoadedError(RuntimeError):
    pass


@dataclass
class DetectionResult:
    label: str
    confidence: float
    top: list[tuple[str, float]] = field(default_factory=list)
    is_threat: bool = False
    low_confidence: bool = False
    severity: str = "none"
    category: str = "benign"

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "confidence": round(self.confidence, 4),
            "top": [[name, round(p, 4)] for name, p in self.top],
            "is_threat": self.is_threat,
            "low_confidence": self.low_confidence,
            "severity": self.severity,
            "category": self.category,
        }


class ThreatDetector:
    """Wraps a trained bundle; safe to call from multiple threads.

    Missing/non-finite features are imputed with the training medians, so a
    partial feature vector can still be classified.
    """

    def __init__(self, bundle: dict, min_confidence: float = 0.55):
        for key in ("model", "feature_names", "classes", "medians"):
            if key not in bundle:
                raise ModelNotLoadedError(f"model bundle is missing {key!r}")
        self.model = bundle["model"]
        self.feature_names: list[str] = list(bundle["feature_names"])
        self.classes: list[str] = list(bundle["classes"])
        self.medians: np.ndarray = np.asarray(bundle["medians"], dtype=np.float64)
        self.metadata: dict = dict(bundle.get("metadata", {}))
        self.metrics: dict = dict(bundle.get("metrics", {}))
        self.min_confidence = float(min_confidence)

    # -- loading ---------------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path, min_confidence: float = 0.55) -> "ThreatDetector":
        path = Path(path)
        if not path.exists():
            raise ModelNotLoadedError(
                f"model file not found: {path}. Train one first: "
                "python scripts/train.py --data <dataset-dir> --out models/"
            )
        bundle = joblib.load(path)
        return cls(bundle, min_confidence=min_confidence)

    # -- inference --------------------------------------------------------------

    def _vector(self, features: Mapping[str, float]) -> np.ndarray:
        vec = np.empty(len(self.feature_names), dtype=np.float64)
        for i, name in enumerate(self.feature_names):
            value = features.get(name, np.nan)
            try:
                value = float(value)
            except (TypeError, ValueError):
                value = np.nan
            if not np.isfinite(value):
                value = float(self.medians[i]) if i < len(self.medians) else 0.0
            vec[i] = value
        return vec.reshape(1, -1)

    def detect(self, features: Mapping[str, float]) -> DetectionResult:
        vec = self._vector(features)

        if hasattr(self.model, "predict_proba"):
            try:
                probs = np.asarray(self.model.predict_proba(vec)[0], dtype=float)
                order = np.argsort(-probs)
                top = [(self.classes[i], float(probs[i]))
                       for i in order[:3] if i < len(self.classes)]
                label = top[0][0] if top else "UNKNOWN"
                confidence = top[0][1] if top else 0.0
            except Exception:
                label = str(self.model.predict(vec)[0])
                confidence = 1.0
                top = [(label, 1.0)]
        else:  # pragma: no cover - all bundled models expose predict_proba
            label = str(self.model.predict(vec)[0])
            confidence = 1.0
            top = [(label, 1.0)]

        low_confidence = confidence < self.min_confidence
        is_threat = is_threat_label(label) and not low_confidence
        return DetectionResult(
            label=label,
            confidence=confidence,
            top=top,
            is_threat=is_threat,
            low_confidence=low_confidence,
            severity=severity_for(label) if is_threat else "none",
            category=category_for(label),
        )

    # -- introspection ------------------------------------------------------------

    def info(self) -> dict:
        return {
            "loaded": True,
            "algorithm": self.metadata.get("algorithm")
                         or type(self.model).__name__,
            "created_at": self.metadata.get("created_at"),
            "dataset": self.metadata.get("dataset"),
            "feature_mode": self.metadata.get("feature_mode", "raw"),
            "n_features": len(self.feature_names),
            "classes": self.classes,
            "min_confidence": self.min_confidence,
            "metrics": {
                "accuracy": self.metrics.get("accuracy"),
                "macro_f1": self.metrics.get("macro_f1"),
                "threat_detection": self.metrics.get("threat_detection"),
            },
            "candidate_models": self.metadata.get("candidate_models", {}),
        }


def safe_load(path: str | Path, min_confidence: float = 0.55):
    """Returns (detector | None, error_message | None)."""
    try:
        return ThreatDetector.load(path, min_confidence=min_confidence), None
    except ModelNotLoadedError as exc:
        return None, str(exc)
    except Exception as exc:  # corrupted bundle etc.
        return None, f"failed to load model: {exc}"
