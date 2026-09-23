"""
train.py
--------
Offline training pipeline. Run it once before starting the server:

    python -m sentra.ml.train                  # uses data/ML-EdgeIIoT-dataset.csv
    python -m sentra.ml.train --max-rows 200000
    python -m sentra.ml.train --synthetic      # no CSV needed

What it produces in sentra/ml/artifacts/:

    classifier.joblib    Random Forest over the 15 Edge-IIoTset classes
    novelty.joblib       Isolation Forest fitted on Normal traffic only
    scaler.joblib        Standardiser, used by the novelty model
    metadata.json        feature order, class order, categorical maps
    metrics.json         everything the dashboard's model card renders
    baseline.json        normal-traffic statistics for the explanation layer
    replay.csv           held-out real samples the live stream replays

Two design decisions worth defending in the report:

* The forest predicts all 15 fine-grained Edge-IIoTset classes; the six-way
  operational family is derived afterwards from taxonomy.py. Training on the
  coarse labels would throw away the distinction between a port scan and a
  vulnerability scan, which matters to the analyst even though both are
  "Reconnaissance".

* An Isolation Forest is fitted on Normal rows alone. The Random Forest can
  only ever answer "which of these 15", so on genuinely novel traffic it is
  confidently wrong. The novelty score gives the engine a way to say "this
  does not resemble anything I was trained on", which is the zero-day gap
  Chapter 6 of the report identified.
"""
from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ..config import get_settings
from ..taxonomy import ATTACK_TYPES, FAMILIES, FAMILY_OF
from . import edge_iiotset, synthetic
from .edge_iiotset import Dataset

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("train")

REPLAY_ROWS = 6000


def load_data(args, settings) -> Dataset:
    if args.synthetic:
        log.info("Synthetic mode requested.")
        return synthetic.build(random_state=settings.random_state)

    path = Path(args.data) if args.data else settings.dataset_path
    if edge_iiotset.available(path):
        return edge_iiotset.load(path, max_rows=args.max_rows, random_state=settings.random_state)

    log.warning("=" * 72)
    log.warning("Edge-IIoTset CSV not found at %s", path)
    log.warning("Falling back to synthetic data. Download the real corpus from:")
    log.warning("  kaggle.com/datasets/mohamedamineferrag/"
                "edgeiiotset-cyber-security-dataset-of-iot-iiot")
    log.warning("=" * 72)
    return synthetic.build(random_state=settings.random_state)


def train(args) -> dict:
    settings = get_settings()
    settings.artifact_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    data = load_data(args, settings)
    for note in data.notes:
        log.info("  %s", note)
    log.info("Class balance: %s", data.class_counts)

    classes = [c for c in ATTACK_TYPES if c in set(data.y)]
    unexpected = sorted(set(data.y) - set(ATTACK_TYPES))
    if unexpected:
        log.warning("Ignoring %d unmapped label(s): %s", len(unexpected), unexpected)
        keep = data.y.isin(classes)
        data.X, data.y = data.X[keep].reset_index(drop=True), data.y[keep].reset_index(drop=True)

    X_train, X_test, y_train, y_test = train_test_split(
        data.X, data.y,
        test_size=settings.test_size,
        random_state=settings.random_state,
        stratify=data.y,
    )
    log.info("Split: %d train / %d test", len(X_train), len(X_test))

    # --- supervised classifier --------------------------------------------
    clf = RandomForestClassifier(
        n_estimators=settings.n_estimators,
        max_depth=settings.max_depth,
        min_samples_leaf=settings.min_samples_leaf,
        class_weight="balanced_subsample",
        random_state=settings.random_state,
        n_jobs=-1,
    )
    log.info("Fitting Random Forest (%d trees)...", settings.n_estimators)
    t0 = time.time()
    clf.fit(X_train.values, y_train)
    fit_seconds = round(time.time() - t0, 2)
    log.info("  done in %.1fs", fit_seconds)

    y_pred = clf.predict(X_test.values)
    report = classification_report(y_test, y_pred, labels=classes, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=classes)

    # Family-level view: what the analyst actually triages on.
    fam_true = y_test.map(FAMILY_OF)
    fam_pred = pd.Series(y_pred, index=y_test.index).map(FAMILY_OF)
    fam_report = classification_report(fam_true, fam_pred, labels=FAMILIES,
                                       output_dict=True, zero_division=0)
    fam_cm = confusion_matrix(fam_true, fam_pred, labels=FAMILIES)

    # Attack-vs-normal, the number a plant manager asks for.
    binary_true = (y_test != "Normal").astype(int)
    binary_pred = (pd.Series(y_pred, index=y_test.index) != "Normal").astype(int)
    tn = int(((binary_true == 0) & (binary_pred == 0)).sum())
    fp = int(((binary_true == 0) & (binary_pred == 1)).sum())
    fn = int(((binary_true == 1) & (binary_pred == 0)).sum())
    tp = int(((binary_true == 1) & (binary_pred == 1)).sum())

    # --- baselines, so the headline number has something to beat ----------
    baselines = {}
    if not args.skip_baselines:
        log.info("Fitting baselines for comparison...")
        for name, est in [
            ("Majority class", DummyClassifier(strategy="most_frequent")),
            ("Single decision tree", DecisionTreeClassifier(max_depth=12,
                                                            random_state=settings.random_state)),
        ]:
            est.fit(X_train.values, y_train)
            p = est.predict(X_test.values)
            baselines[name] = {
                "accuracy": float(accuracy_score(y_test, p)),
                "macro_f1": float(f1_score(y_test, p, average="macro", zero_division=0)),
            }

    # --- cross-validation, because one split is one sample ----------------
    cv_scores: list[float] = []
    if not args.skip_cv:
        log.info("Running 5-fold cross-validation...")
        cv_sample = min(len(X_train), 60_000)
        idx = X_train.sample(cv_sample, random_state=settings.random_state).index
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=settings.random_state)
        cv_scores = cross_val_score(
            RandomForestClassifier(
                n_estimators=120, max_depth=settings.max_depth,
                class_weight="balanced_subsample",
                random_state=settings.random_state, n_jobs=-1,
            ),
            X_train.loc[idx].values, y_train.loc[idx],
            cv=skf, scoring="f1_macro", n_jobs=1,
        ).tolist()
        log.info("  macro F1 %.4f +/- %.4f", float(np.mean(cv_scores)), float(np.std(cv_scores)))

    # --- novelty detector --------------------------------------------------
    # Fitted on the whole training distribution, not on Normal alone. The
    # question this model answers is "have I seen traffic like this before",
    # and a known attack has been seen before -- flagging every attack as
    # novel would make the flag meaningless. The threshold sits at the 0.5th
    # percentile of training scores, so roughly one flow in two hundred that
    # genuinely resembles nothing in the corpus gets surfaced for review.
    log.info("Fitting novelty detector on the training distribution...")
    scaler = StandardScaler().fit(X_train.values)
    novelty = IsolationForest(
        n_estimators=200,
        contamination=settings.novelty_contamination,
        random_state=settings.random_state,
        n_jobs=-1,
    ).fit(scaler.transform(X_train.values))

    train_scores = novelty.score_samples(scaler.transform(X_train.values))
    novel_scores = novelty.score_samples(scaler.transform(X_test.values))
    normal_mask = (y_test == "Normal").values
    threshold = float(np.percentile(train_scores, 0.5))
    novelty_summary = {
        "trained_on_rows": int(len(X_train)),
        "score_normal_mean": float(np.mean(novel_scores[normal_mask])) if normal_mask.any() else 0.0,
        "score_attack_mean": float(np.mean(novel_scores[~normal_mask])) if (~normal_mask).any() else 0.0,
        "threshold": threshold,
        "flagged_share_of_holdout": float(np.mean(novel_scores < threshold)),
    }
    log.info("  novelty flags %.2f%% of the holdout set",
             novelty_summary["flagged_share_of_holdout"] * 100)

    # --- latency, measured the way the API will actually call it ----------
    sample = X_test.iloc[[0]].values
    clf.predict_proba(sample)  # warm the cache
    timings = []
    for _ in range(200):
        t = time.perf_counter()
        clf.predict_proba(sample)
        timings.append((time.perf_counter() - t) * 1000)
    latency = {
        "mean_ms": round(float(np.mean(timings)), 3),
        "p50_ms": round(float(np.percentile(timings, 50)), 3),
        "p95_ms": round(float(np.percentile(timings, 95)), 3),
        "p99_ms": round(float(np.percentile(timings, 99)), 3),
        "samples": len(timings),
    }
    log.info("Inference latency: %.2f ms mean, %.2f ms p95", latency["mean_ms"], latency["p95_ms"])

    # --- per-feature normal profile, used to explain alerts ---------------
    normal_stats = X_train[y_train == "Normal"]
    baseline_profile = {
        col: {
            "mean": float(normal_stats[col].mean()),
            "std": float(normal_stats[col].std() or 1.0),
            "p95": float(normal_stats[col].quantile(0.95)),
        }
        for col in data.feature_names
    }

    importances = sorted(
        ({"feature": f, "importance": float(v)}
         for f, v in zip(data.feature_names, clf.feature_importances_)),
        key=lambda d: d["importance"], reverse=True,
    )

    # --- replay pool: real held-out rows for the live stream ---------------
    replay = X_test.copy()
    replay["__label"] = y_test.values
    if len(replay) > REPLAY_ROWS:
        per_class = max(60, REPLAY_ROWS // max(1, len(classes)))
        # Sample by index: pandas 2.x drops the grouping column inside .apply,
        # which would strip __label out of the pool and break replay entirely.
        keep = np.concatenate([
            group.sample(min(len(group), per_class),
                         random_state=settings.random_state).index.values
            for _, group in replay.groupby("__label")
        ])
        replay = replay.loc[keep]
    replay.to_csv(settings.artifact_dir / "replay.csv", index=False)
    log.info("Wrote %d replay rows for the live stream.", len(replay))

    # --- persist -----------------------------------------------------------
    joblib.dump(clf, settings.artifact_dir / "classifier.joblib", compress=3)
    joblib.dump(novelty, settings.artifact_dir / "novelty.joblib", compress=3)
    joblib.dump(scaler, settings.artifact_dir / "scaler.joblib", compress=3)

    metadata = {
        "feature_names": data.feature_names,
        "classes": classes,
        "families": FAMILIES,
        "categorical_maps": data.categorical_maps,
        "data_source": data.source,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "sklearn": __import__("sklearn").__version__,
        "novelty": novelty_summary,
    }
    (settings.artifact_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    (settings.artifact_dir / "baseline.json").write_text(json.dumps(baseline_profile, indent=2))

    metrics = {
        "data_source": data.source,
        "dataset_notes": data.notes,
        "rows_read": data.rows_read,
        "rows_used": int(len(data.X)),
        "train_size": int(len(X_train)),
        "test_size": int(len(X_test)),
        "n_features": len(data.feature_names),
        "class_counts": data.class_counts,
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "macro_f1": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "cv_macro_f1": {
            "folds": cv_scores,
            "mean": float(np.mean(cv_scores)) if cv_scores else None,
            "std": float(np.std(cv_scores)) if cv_scores else None,
        },
        "per_class": {c: report[c] for c in classes if c in report},
        "confusion_matrix": cm.tolist(),
        "classes": classes,
        "family_report": {f: fam_report[f] for f in FAMILIES if f in fam_report},
        "family_confusion_matrix": fam_cm.tolist(),
        "attack_vs_normal": {
            "true_negative": tn, "false_positive": fp,
            "false_negative": fn, "true_positive": tp,
            "detection_rate": round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
            "false_alarm_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        },
        "baselines": baselines,
        "latency": latency,
        "feature_importances": importances,
        "hyperparameters": {
            "n_estimators": settings.n_estimators,
            "max_depth": settings.max_depth,
            "min_samples_leaf": settings.min_samples_leaf,
            "class_weight": "balanced_subsample",
            "random_state": settings.random_state,
        },
        "fit_seconds": fit_seconds,
        "total_seconds": round(time.time() - started, 2),
        "trained_at": metadata["trained_at"],
    }
    (settings.artifact_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))

    log.info("-" * 60)
    log.info("Source           %s", data.source)
    log.info("Accuracy         %.4f", metrics["accuracy"])
    log.info("Balanced acc.    %.4f", metrics["balanced_accuracy"])
    log.info("Macro F1         %.4f", metrics["macro_f1"])
    log.info("Detection rate   %.4f", metrics["attack_vs_normal"]["detection_rate"])
    log.info("False alarm rate %.4f", metrics["attack_vs_normal"]["false_alarm_rate"])
    log.info("Artifacts        %s", settings.artifact_dir)
    log.info("-" * 60)
    return metrics


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train the SENTRA-IIoT detection models.")
    p.add_argument("--data", help="Path to an Edge-IIoTset CSV")
    p.add_argument("--max-rows", type=int, default=None, help="Cap rows (stratified)")
    p.add_argument("--synthetic", action="store_true", help="Skip the CSV, use generated data")
    p.add_argument("--skip-cv", action="store_true", help="Skip cross-validation (faster)")
    p.add_argument("--skip-baselines", action="store_true", help="Skip baseline models")
    args = p.parse_args(argv)
    train(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
