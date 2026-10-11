"""Training pipeline: CIC-IDS2017 -> RF / XGBoost -> versioned model bundle.

The bundle saved by this module is a self-contained joblib dict::

    {
      "model":          fitted estimator (predict_proba-compatible),
      "feature_names":  list[str] — canonical schema order,
      "classes":        list[str] — human labels aligned to predict_proba cols,
      "medians":        np.ndarray — per-feature train medians (NaN fill),
      "metadata":       dict  — dataset, params, timings, versions,
      "metrics":        dict  — hold-out test metrics (src.ml.evaluate),
    }
"""
from __future__ import annotations

import json
import platform
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from src import __version__
from src.dataset.cicids2017 import TARGET_COLUMN, load_dataset, summarize_labels
from src.features.schema import CANONICAL_FEATURES, BENIGN
from src.ml.evaluate import evaluate_predictions, save_metrics

try:  # optional dependency — training degrades to RF-only if missing
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:  # pragma: no cover - environment specific
    XGBClassifier = None  # type: ignore[assignment]
    HAS_XGB = False


class TrainingError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Feature-mode: raw CSV columns vs live-extracted features
# --------------------------------------------------------------------------

# Columns the flow renderer needs to reconstruct a flow's packet stream.
_RENDERER_FIELDS = [
    "fwd_packets", "protocol", "fwd_pkt_len_min", "fwd_pkt_len_max",
    "fwd_pkt_len_mean", "syn_flag_count", "ack_flag_count", "psh_flag_count",
    "fin_flag_count", "rst_flag_count", "urg_flag_count", "fwd_seg_size_avg",
    "act_data_pkt_fwd", "min_seg_size_fwd", "duration_us", "fwd_iat_max",
    "idle_max", "init_win_bytes_fwd",
]


def live_features_frame(df, seed: int = 7, verbose: bool = True):
    """Re-derive every flow row's features through the LIVE extractor.

    Each dataset row is rendered into a synthetic packet stream and folded
    through the same FlowAccumulator the sensor uses at runtime. The result
    is a training matrix in the sensor's own feature semantics — immune to
    the CICFlowMeter CSV artefacts (impossible packet lengths, bidirectional
    IATs) that would otherwise skew the model.
    """
    import numpy as np

    from src.features.flow_features import FlowAccumulator
    from src.synthesis.render import render_flow_packets

    rng = random.Random(seed)
    labels = df[TARGET_COLUMN].to_numpy()
    fields = {name: df[name].to_numpy() for name in _RENDERER_FIELDS}

    n = len(df)
    out = np.zeros((n, len(CANONICAL_FEATURES)), dtype=np.float64)
    for i in range(n):
        row = {name: float(arr[i]) for name, arr in fields.items()}
        packets = render_flow_packets(row, "10.0.0.1", "10.0.0.2", 1234, 80,
                                      base_ts_us=i * 300_000_000, rng=rng)
        acc = FlowAccumulator(("10.0.0.1", 1234, "10.0.0.2", 80,
                               int(row["protocol"])))
        for pkt in packets:
            acc.add(pkt)
        cf = acc.finish("final")
        out[i] = [cf.features[name] for name in CANONICAL_FEATURES]

    live_df = pd.DataFrame(out, columns=CANONICAL_FEATURES)
    live_df[TARGET_COLUMN] = labels
    if verbose:
        print(f"      rendered {n:,} flows through the live feature extractor")
    return live_df


# --------------------------------------------------------------------------
# Training
# --------------------------------------------------------------------------

def _prepare_xy(df) -> tuple[np.ndarray, np.ndarray]:
    X = df[CANONICAL_FEATURES].replace([np.inf, -np.inf], np.nan).to_numpy(dtype=np.float64)
    y = df[TARGET_COLUMN].to_numpy()
    return X, y


def _fit_random_forest(X, y, cfg, seed: int):
    return RandomForestClassifier(
        n_estimators=cfg.n_estimators,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=seed,
    ).fit(X, y)


def _fit_xgboost(X, y_enc, cfg, seed: int, n_classes: int):
    if not HAS_XGB:
        raise TrainingError("xgboost is not installed")
    counts = np.bincount(y_enc, minlength=n_classes)
    weights = len(y_enc) / (n_classes * np.maximum(counts, 1))
    sample_weight = weights[y_enc]
    model = XGBClassifier(
        n_estimators=max(cfg.n_estimators, 300),
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        n_jobs=-1,
        random_state=seed,
        eval_metric="mlogloss" if n_classes > 2 else "logloss",
        verbosity=1,
    )
    model.fit(X, y_enc, sample_weight=sample_weight)
    return model


def _classes_for(model, le: LabelEncoder | None) -> list[str]:
    """Human-readable classes aligned with predict_proba column order."""
    if le is not None:
        return [str(c) for c in le.inverse_transform(model.classes_)]
    return [str(c) for c in model.classes_]


def _feature_importances(model, feature_names: list[str]) -> list[dict]:
    try:
        imps = np.asarray(model.feature_importances_, dtype=float)
    except AttributeError:
        return []
    pairs = sorted(zip(feature_names, imps.tolist()),
                   key=lambda kv: kv[1], reverse=True)
    return [{"feature": name, "importance": round(val, 6)} for name, val in pairs]


def train_model(
    data: str | Path,
    out_dir: str | Path,
    cfg,
    max_per_class: int | None = None,
    use_xgboost: bool | None = None,
    feature_mode: str = "live",
    verbose: bool = True,
) -> dict:
    """Train, evaluate and persist the best model. Returns a result summary.

    feature_mode:
      * "live" — render every dataset flow through the sensor's own feature
        extractor and train on those features (recommended: guarantees
        train/serve consistency with the packet pipeline);
      * "raw"  — train directly on the CICFlowMeter CSV columns.
    """
    if feature_mode not in ("live", "raw"):
        raise ValueError(f"unknown feature_mode: {feature_mode!r}")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cap = cfg.max_samples_per_class if max_per_class is None else max_per_class
    want_xgb = cfg.use_xgboost if use_xgboost is None else use_xgboost

    t_start = time.perf_counter()
    if verbose:
        print(f"[1/5] loading dataset from {data} ...")
    df = load_dataset(data, max_per_class=cap, verbose=verbose)

    label_counts = summarize_labels(df)
    n_classes = len(label_counts)
    if n_classes < 2:
        raise TrainingError(
            f"only one class present ({list(label_counts)}). The training data "
            "must contain BENIGN *and* attack flows — e.g. include the "
            "Wednesday/Tuesday/Friday parts of CIC-IDS2017, not just Monday."
        )
    if verbose:
        print(f"[2/5] {len(df):,} flows, {n_classes} classes:")
        for label, count in sorted(label_counts.items(), key=lambda kv: -kv[1]):
            print(f"        {label:<32} {count:>10,}")

    # Drop classes with <2 samples (cannot survive a stratified split).
    tiny = [label for label, count in label_counts.items() if count < 2]
    if tiny:
        if verbose:
            print(f"      dropping class(es) with <2 samples: {tiny}")
        df = df[~df[TARGET_COLUMN].isin(tiny)]
        label_counts = summarize_labels(df)

    if feature_mode == "live":
        if verbose:
            print("[2b/5] re-deriving features through the live extractor "
                  "(train/serve consistency) ...")
        df = live_features_frame(df, seed=cfg.random_state, verbose=verbose)
        # degenerate rows (all-zero features) carry no signal
        df = df[df[CANONICAL_FEATURES].to_numpy().sum(axis=1) > 0].reset_index(drop=True)

    X, y = _prepare_xy(df)
    del df

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=cfg.test_size,
        random_state=cfg.random_state,
        stratify=y,
    )
    if verbose:
        print(f"[3/5] split: {len(X_train):,} train / {len(X_test):,} test rows")

    # NaN fill with TRAIN medians only (no leakage into the hold-out).
    medians = np.nanmedian(X_train, axis=0)
    medians = np.where(np.isfinite(medians), medians, 0.0)
    X_train = np.where(np.isfinite(X_train), X_train, np.where(np.isnan(X_train), medians, 0.0))
    X_test = np.where(np.isnan(X_test), medians, X_test)
    # any remaining +/-inf (impossible after median fill, but be safe):
    X_train = np.where(np.isfinite(X_train), X_train, 0.0)
    X_test = np.where(np.isfinite(X_test), X_test, 0.0)

    results: dict[str, dict] = {}

    # -- Random Forest --------------------------------------------------------
    if verbose:
        print(f"[4/5] training Random Forest ({cfg.n_estimators} trees) ...")
    t0 = time.perf_counter()
    rf = _fit_random_forest(X_train, y_train, cfg, cfg.random_state)
    rf_time = time.perf_counter() - t0
    rf_pred = rf.predict(X_test)
    rf_metrics = evaluate_predictions(y_test, rf_pred, list(rf.classes_))
    rf_metrics["train_time_s"] = round(rf_time, 2)
    results["random_forest"] = {"model": rf, "le": None, "metrics": rf_metrics}
    if verbose:
        print(f"      RF  accuracy={rf_metrics['accuracy']:.4f} "
              f"macro_f1={rf_metrics['macro_f1']:.4f} "
              f"({rf_time:.1f}s)")

    # -- XGBoost ---------------------------------------------------------------
    if want_xgb and HAS_XGB:
        if verbose:
            print("      training XGBoost ...")
        le = LabelEncoder().fit(list(label_counts.keys()))
        y_train_enc = le.transform(y_train)
        t0 = time.perf_counter()
        xgb = _fit_xgboost(X_train, y_train_enc, cfg, cfg.random_state,
                           n_classes=len(le.classes_))
        xgb_time = time.perf_counter() - t0
        xgb_pred_enc = xgb.predict(X_test)
        xgb_pred = le.inverse_transform(np.asarray(xgb_pred_enc).astype(int))
        xgb_metrics = evaluate_predictions(y_test, xgb_pred, list(le.classes_))
        xgb_metrics["train_time_s"] = round(xgb_time, 2)
        results["xgboost"] = {"model": xgb, "le": le, "metrics": xgb_metrics}
        if verbose:
            print(f"      XGB accuracy={xgb_metrics['accuracy']:.4f} "
                  f"macro_f1={xgb_metrics['macro_f1']:.4f} "
                  f"({xgb_time:.1f}s)")
    elif want_xgb and not HAS_XGB:
        if verbose:
            print("      xgboost not installed -> Random Forest only")

    # -- pick the best ----------------------------------------------------------
    def score(entry: dict) -> tuple[float, float]:
        m = entry["metrics"]
        return (m["macro_f1"], m["threat_detection"]["recall"])

    best_name = max(results, key=lambda name: score(results[name]))
    best = results[best_name]
    if verbose:
        print(f"[5/5] selected model: {best_name}")

    metadata = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(data),
        "feature_mode": feature_mode,
        "rows": int(len(X_train) + len(X_test)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "n_classes": n_classes,
        "class_counts": label_counts,
        "max_samples_per_class": cap,
        "random_state": cfg.random_state,
        "test_size": cfg.test_size,
        "unithreat_version": __version__,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "feature_count": len(CANONICAL_FEATURES),
        "candidate_models": {
            name: {
                "accuracy": m["accuracy"],
                "macro_f1": m["macro_f1"],
                "threat_recall": m["threat_detection"]["recall"],
                "train_time_s": m["train_time_s"],
            }
            for name, entry in results.items()
            for m in [entry["metrics"]]
        },
    }

    bundle = {
        "model": best["model"],
        "feature_names": list(CANONICAL_FEATURES),
        "classes": _classes_for(best["model"], best["le"]),
        "medians": medians,
        "metadata": metadata,
        "metrics": best["metrics"],
    }
    model_path = out_dir / "latest_model.joblib"
    joblib.dump(bundle, model_path, compress=3)

    save_metrics(best["metrics"], out_dir / "metrics.json")
    (out_dir / "feature_importances.json").write_text(
        json.dumps(_feature_importances(best["model"], list(CANONICAL_FEATURES)), indent=2),
        encoding="utf-8",
    )
    report = _render_report(best_name, results, metadata)
    (out_dir / "training_report.md").write_text(report, encoding="utf-8")

    total = time.perf_counter() - t_start
    if verbose:
        print(f"      saved {model_path}  (total {total:.0f}s)")

    return {
        "model_path": str(model_path),
        "model_name": best_name,
        "metrics": best["metrics"],
        "metadata": metadata,
        "out_dir": str(out_dir),
        "total_time_s": round(total, 1),
    }


# --------------------------------------------------------------------------
# Human-readable report
# --------------------------------------------------------------------------

def _render_report(best_name: str, results: dict, metadata: dict) -> str:
    m = results[best_name]["metrics"]
    lines: list[str] = []
    add = lines.append

    add("# UniThreat training report\n")
    add(f"*Generated {metadata['created_at']} — UniThreat v{metadata['unithreat_version']}*\n")

    add("## Dataset\n")
    add(f"- Source: `{metadata['dataset']}`")
    add(f"- Feature mode: **{metadata.get('feature_mode', 'raw')}** "
        "(`live` = features re-derived through the sensor's own extractor)")
    add(f"- Rows: {metadata['rows']:,} (train {metadata['train_rows']:,} / "
        f"test {metadata['test_rows']:,})")
    add(f"- Classes: {metadata['n_classes']}")
    if metadata.get("max_samples_per_class"):
        add(f"- Per-class cap: {metadata['max_samples_per_class']:,}")
    add("- Features: 43 canonical one-way flow features\n")

    add("## Candidate models (hold-out test set)\n")
    add("| model | accuracy | macro F1 | threat recall | train time |")
    add("|---|---|---|---|---|")
    for name, entry in results.items():
        mm = entry["metrics"]
        add(f"| {name} | {mm['accuracy']:.4f} | {mm['macro_f1']:.4f} "
            f"| {mm['threat_detection']['recall']:.4f} | {mm['train_time_s']}s |")
    add(f"\n**Selected: {best_name}**\n")

    add("## Threat detection (binary: any attack vs benign)\n")
    td = m["threat_detection"]
    add(f"- precision {td['precision']:.4f} — recall (detection rate) "
        f"{td['recall']:.4f} — F1 {td['f1']:.4f}")
    add(f"- TP {td['true_positives']:,} / FN {td['false_negatives']:,} "
        f"/ FP {td['false_positives']:,} / TN {td['true_negatives']:,}\n")

    add("## Per-class performance\n")
    add("| class | precision | recall | F1 | support |")
    add("|---|---|---|---|---|")
    for label, stats in sorted(m["per_class"].items(),
                               key=lambda kv: -kv[1]["support"]):
        add(f"| {label} | {stats['precision']:.4f} | {stats['recall']:.4f} "
            f"| {stats['f1']:.4f} | {stats['support']:,} |")

    add("\n## Confusion matrix (rows = true, cols = predicted)\n")
    labels = m["confusion_labels"]
    add("| true \\ pred | " + " | ".join(labels) + " |")
    add("|---" * (len(labels) + 1) + "|")
    for label, row in zip(labels, m["confusion_matrix"]):
        add(f"| **{label}** | " + " | ".join(str(v) for v in row) + " |")

    add("\n## Top features\n")
    add("```")
    for name, entry in results.items():
        imps = _feature_importances(entry["model"], list(CANONICAL_FEATURES))
        if imps:
            add(f"[{name}]")
            for item in imps[:15]:
                bar = "#" * int(item["importance"] * 60)
                add(f"  {item['feature']:<24} {item['importance']:.4f} {bar}")
    add("```\n")

    add("## Reproducing\n")
    add("```bash")
    add("python scripts/train.py --data data/raw/cicids2017/traffic_labels "
        "--out models/")
    add("```")
    return "\n".join(lines) + "\n"
