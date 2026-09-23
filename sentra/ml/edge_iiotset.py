"""
edge_iiotset.py
---------------
Loads the Edge-IIoTset corpus (Ferrag, Friha, Hamouda, Maglaras & Janicke,
IEEE Access 2022) from data/ and hands back a clean, model-ready matrix.

Get the data:
    https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot

Put either CSV in data/:
    ML-EdgeIIoT-dataset.csv    ~157k rows, pre-sampled, trains in ~1 min
    DNN-EdgeIIoT-dataset.csv   ~2.2M rows, full corpus, needs max_rows or ~6GB

Nothing else in the project reaches for the file directly -- if the CSV is
missing, train.py falls back to the synthetic generator and says so loudly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from .schema import CATEGORICAL_COLUMNS, DROP_COLUMNS, LABEL_COLUMN

log = logging.getLogger(__name__)


@dataclass
class Dataset:
    """A loaded, cleaned corpus plus everything needed to reproduce it."""

    X: pd.DataFrame
    y: pd.Series
    source: str                      # "edge-iiotset" or "synthetic"
    feature_names: list[str]
    categorical_maps: dict[str, dict[str, int]]
    rows_read: int
    rows_kept: int
    notes: list[str]

    @property
    def class_counts(self) -> dict[str, int]:
        return {k: int(v) for k, v in self.y.value_counts().items()}


def available(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


def load(path: Path, max_rows: int | None = None, random_state: int = 42) -> Dataset:
    """Read, clean and encode Edge-IIoTset. Raises FileNotFoundError if absent."""
    if not available(path):
        raise FileNotFoundError(
            f"{path} not found. Download Edge-IIoTset from Kaggle and place the "
            f"CSV in {path.parent}, or run training with --synthetic."
        )

    notes: list[str] = []
    log.info("Reading %s", path.name)
    df = pd.read_csv(path, low_memory=False)
    rows_read = len(df)
    notes.append(f"Read {rows_read:,} rows and {df.shape[1]} columns from {path.name}.")

    if LABEL_COLUMN not in df.columns:
        raise ValueError(
            f"{path.name} has no '{LABEL_COLUMN}' column. This does not look "
            "like an Edge-IIoTset export."
        )

    # Edge-IIoTset contains exact duplicate rows; keeping them inflates accuracy
    # because identical samples land in both train and test.
    before = len(df)
    df = df.drop_duplicates()
    if len(df) < before:
        notes.append(f"Dropped {before - len(df):,} exact duplicate rows.")

    df = df.dropna(subset=[LABEL_COLUMN])
    y = df[LABEL_COLUMN].astype(str).str.strip()

    # Optional subsample, stratified so rare classes survive.
    if max_rows and len(df) > max_rows:
        frac = max_rows / len(df)
        idx = (
            df.groupby(y, group_keys=False)
            .apply(lambda g: g.sample(max(1, int(len(g) * frac)), random_state=random_state))
            .index
        )
        df = df.loc[idx]
        y = y.loc[idx]
        notes.append(f"Stratified subsample to {len(df):,} rows (max_rows={max_rows:,}).")

    X = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns], errors="ignore")
    notes.append(
        f"Removed {df.shape[1] - X.shape[1]} leakage/label columns "
        "(addresses, timestamps, raw payloads, URIs)."
    )

    # Encode the handful of string columns that survive. Stored as explicit
    # maps rather than sklearn encoders so inference can handle unseen values
    # without throwing.
    categorical_maps: dict[str, dict[str, int]] = {}
    for col in X.columns:
        if X[col].dtype == object or col in CATEGORICAL_COLUMNS:
            values = X[col].astype(str).fillna("")
            levels = sorted(values.unique())
            mapping = {v: i for i, v in enumerate(levels)}
            categorical_maps[col] = mapping
            X[col] = values.map(mapping).astype(np.int32)

    X = X.apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32)

    # Constant columns carry no signal and only slow the forest down.
    constant = [c for c in X.columns if X[c].nunique() <= 1]
    if constant:
        X = X.drop(columns=constant)
        categorical_maps = {k: v for k, v in categorical_maps.items() if k in X.columns}
        notes.append(f"Dropped {len(constant)} constant columns.")

    notes.append(f"Final feature space: {X.shape[1]} columns.")

    return Dataset(
        X=X.reset_index(drop=True),
        y=y.reset_index(drop=True),
        source="edge-iiotset",
        feature_names=list(X.columns),
        categorical_maps=categorical_maps,
        rows_read=rows_read,
        rows_kept=len(X),
        notes=notes,
    )
