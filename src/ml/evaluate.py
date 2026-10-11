"""Model evaluation helpers (train-time and test-time metrics)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from src.features.schema import BENIGN, is_threat_label

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def threat_binary(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    """Binary (any-attack vs benign) detection metrics."""
    t = np.array([is_threat_label(str(v)) for v in y_true], dtype=int)
    p = np.array([is_threat_label(str(v)) for v in y_pred], dtype=int)
    tp = int(((t == 1) & (p == 1)).sum())
    fn = int(((t == 1) & (p == 0)).sum())
    fp = int(((t == 0) & (p == 1)).sum())
    tn = int(((t == 0) & (p == 0)).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positives": tp, "false_negatives": fn,
        "false_positives": fp, "true_negatives": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "accuracy": round((tp + tn) / max(len(t), 1), 6),
    }


def evaluate_predictions(y_true, y_pred, classes: list[str]) -> dict:
    """Full metric bundle: overall + per-class + binary threat detection."""
    labels = list(classes)
    report = classification_report(
        y_true, y_pred, labels=labels, output_dict=True, zero_division=0
    )
    per_class = {
        label: {
            "precision": round(float(report[label]["precision"]), 6),
            "recall": round(float(report[label]["recall"]), 6),
            "f1": round(float(report[label]["f1-score"]), 6),
            "support": int(float(report[label]["support"])),
        }
        for label in labels if label in report
    }
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 6),
        "macro_f1": round(float(f1_score(y_true, y_pred, labels=labels,
                                          average="macro", zero_division=0)), 6),
        "weighted_f1": round(float(f1_score(y_true, y_pred, labels=labels,
                                            average="weighted", zero_division=0)), 6),
        "macro_precision": round(float(precision_score(y_true, y_pred, labels=labels,
                                                       average="macro", zero_division=0)), 6),
        "macro_recall": round(float(recall_score(y_true, y_pred, labels=labels,
                                                 average="macro", zero_division=0)), 6),
        "per_class": per_class,
        "threat_detection": threat_binary(np.asarray(y_true), np.asarray(y_pred)),
        "confusion_matrix": confusion_matrix(
            y_true, y_pred, labels=labels
        ).astype(int).tolist(),
        "confusion_labels": labels,
        "benign_flows": int(sum(1 for v in y_true if str(v) == BENIGN)),
        "attack_flows": int(sum(1 for v in y_true if str(v) != BENIGN)),
    }


def save_metrics(metrics: dict, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
