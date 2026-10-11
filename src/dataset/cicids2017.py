"""CIC-IDS2017 dataset loading and canonicalisation.

Supports every common distribution of the dataset:

  * original ``MachineLearningCVE`` CSVs   (8 files, ~884 MB)
  * original ``TrafficLabelling`` CSVs    (GeneratedLabelledFlows)
  * parquet mirrors of either (e.g. the Hugging Face datasets the downloader
    fetches), including the ``traffic_labels`` variant with Protocol/IPs

Every variant is mapped onto the canonical one-way feature schema
(:mod:`src.features.schema`), cleaned (inf/NaN), and label-normalised.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

from src.features.schema import (
    BENIGN,
    CANONICAL_FEATURES,
    canonical_column_map,
    find_label_column,
    normalize_label,
)

TARGET_COLUMN = "label"


class DatasetError(ValueError):
    """Raised when a dataset file cannot be interpreted."""


def _read_one(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    # CIC-IDS2017 CSVs occasionally carry a BOM and/or stray high bytes.
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return pd.read_csv(path, encoding=encoding, low_memory=False)
        except UnicodeDecodeError:
            continue
    raise DatasetError(f"could not decode {path}")


def canonicalize(df: pd.DataFrame, origin: str = "unknown") -> pd.DataFrame:
    """Map a raw CIC-IDS2017 frame onto ``CANONICAL_FEATURES`` + ``label``."""
    if df.empty:
        raise DatasetError(f"empty dataset frame ({origin})")
    columns = [str(c) for c in df.columns]
    try:
        mapping = canonical_column_map(columns)
    except KeyError as exc:
        raise DatasetError(f"{origin}: {exc}") from exc
    label_col = find_label_column(columns)

    out = pd.DataFrame(index=df.index)
    for canonical in CANONICAL_FEATURES:
        series = df[mapping[canonical]]
        out[canonical] = pd.to_numeric(series, errors="coerce")
    out[TARGET_COLUMN] = df[label_col].map(normalize_label)

    # Some dataset mirrors contain rows with missing labels (e.g. duplicated
    # flows whose label got lost during conversion). Those rows are unusable
    # for supervised training and must never become a "nan" class.
    raw_label = df[label_col]
    invalid = raw_label.isna() \
        | raw_label.astype(str).str.strip().eq("") \
        | raw_label.astype(str).str.strip().str.lower().isin({"nan", "none", "null"})
    if invalid.any():
        out = out[~invalid]
    if out.empty:
        raise DatasetError(f"{origin}: no usable labeled rows")
    return out


def iter_frames(paths: Iterable[Path]):
    for path in paths:
        yield canonicalize(_read_one(Path(path)), origin=str(path))


def collect_paths(data: str | Path) -> list[Path]:
    """Resolve a dir/glob/file into a list of dataset part files."""
    p = Path(data)
    if p.is_dir():
        found = sorted(
            list(p.glob("*.csv")) + list(p.glob("*.parquet")) +
            list(p.glob("*.csv.gz"))
        )
        if not found:
            raise DatasetError(f"no dataset files (.csv/.parquet) under {p}")
        return found
    if str(data).count("*") or str(data).count("?"):
        found = sorted(Path().glob(str(data)))
        if not found:
            raise DatasetError(f"glob {data!r} matched nothing")
        return found
    return [p]


def load_dataset(data: str | Path,
                 max_per_class: int = 0,
                 verbose: bool = True) -> pd.DataFrame:
    """Load + concat + (optionally) per-class-cap the dataset.

    ``max_per_class`` keeps training tractable on the heavily imbalanced
    classes (PortScan/DoS Hulk dominate; Heartbleed has 11 samples).
    """
    paths = collect_paths(data)
    frames = []
    for i, frame in enumerate(iter_frames(paths), start=1):
        frames.append(frame)
        if verbose:
            print(f"  [{i}/{len(paths)}] loaded {Path(paths[i - 1]).name}: "
                  f"{len(frame):,} flows")
    df = pd.concat(frames, ignore_index=True)

    if max_per_class and max_per_class > 0:
        df = df.groupby(TARGET_COLUMN, group_keys=False).head(max_per_class)
        df = df.reset_index(drop=True)
        if verbose:
            print(f"  capped at {max_per_class:,} flows per class -> {len(df):,} rows")
    return df


def clean_features(df: pd.DataFrame) -> pd.DataFrame:
    """Replace +/-inf with NaN (CIC-IDS2017's famous Flow Bytes/s artefacts)."""
    feats = df[CANONICAL_FEATURES].replace([np.inf, -np.inf], np.nan)
    return feats


def summarize_labels(df: pd.DataFrame) -> dict[str, int]:
    counts = df[TARGET_COLUMN].value_counts()
    return {str(k): int(v) for k, v in counts.items()}


def is_only_benign(df: pd.DataFrame) -> bool:
    return (df[TARGET_COLUMN] == BENIGN).all()
