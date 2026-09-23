"""
engine.py
---------
The detection engine. One object, loaded once at startup, that turns a raw
feature dictionary into a fully-formed alert.

The pipeline for a single sample:

    align features  ->  Random Forest probabilities  ->  novelty score
                    ->  deviation analysis  ->  narrative  ->  Alert

Deviation analysis is worth a note. The forest can report global feature
importance, but that is a property of the model, not of this packet. To
explain one specific alert we combine two things: how far each feature sits
from quiet-hours normal (a z-score against baseline.json) and how much the
model cares about that feature overall. The product ranks what to show the
analyst, which is a cheap local approximation of a SHAP attribution and runs
in microseconds rather than seconds -- an important property when the NFR
budget for the whole classification is a few milliseconds.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from .config import get_settings
from .ml.schema import friendly
from .narrator import describe_deviation, summarise
from .taxonomy import profile as threat_profile

log = logging.getLogger(__name__)


class ModelNotTrained(RuntimeError):
    """Raised when the server starts before `python -m sentra.ml.train` has run."""


class DetectionEngine:
    def __init__(self, artifact_dir: Path | None = None):
        settings = get_settings()
        self.dir = artifact_dir or settings.artifact_dir
        self.low_confidence = settings.low_confidence_threshold
        self._lock = threading.Lock()
        self._load()

    # -- lifecycle ---------------------------------------------------------

    def _load(self) -> None:
        required = ["classifier.joblib", "metadata.json", "metrics.json", "baseline.json"]
        missing = [f for f in required if not (self.dir / f).exists()]
        if missing:
            raise ModelNotTrained(
                "Model artifacts are missing: "
                + ", ".join(missing)
                + ".\nRun:  python -m sentra.ml.train"
            )

        self.classifier = joblib.load(self.dir / "classifier.joblib")
        self.metadata: dict = json.loads((self.dir / "metadata.json").read_text())
        self.metrics: dict = json.loads((self.dir / "metrics.json").read_text())
        self.baseline: dict = json.loads((self.dir / "baseline.json").read_text())

        self.features: list[str] = self.metadata["feature_names"]
        self.classes: list[str] = list(self.classifier.classes_)
        self.categorical_maps: dict = self.metadata.get("categorical_maps", {})

        self.novelty = None
        self.scaler = None
        if (self.dir / "novelty.joblib").exists() and (self.dir / "scaler.joblib").exists():
            self.novelty = joblib.load(self.dir / "novelty.joblib")
            self.scaler = joblib.load(self.dir / "scaler.joblib")
            self.novelty_threshold = self.metadata.get("novelty", {}).get("threshold", -0.55)

        self.importance = dict(zip(self.features, self.classifier.feature_importances_))
        log.info(
            "Engine ready: %d features, %d classes, source=%s",
            len(self.features), len(self.classes), self.metadata.get("data_source"),
        )

    def reload(self) -> None:
        with self._lock:
            self._load()

    # -- feature handling --------------------------------------------------

    def align(self, sample: dict[str, Any]) -> np.ndarray:
        """Build the model's feature vector from a partial, messy dictionary.

        Missing features fall back to the normal-traffic mean rather than zero.
        Zero is a real measurement in most of these columns, and substituting
        it silently pushes a sample toward whichever class lives near the
        origin. The baseline mean is the honest "no information" value.
        """
        row = np.empty(len(self.features), dtype=np.float32)
        for i, col in enumerate(self.features):
            value = sample.get(col)
            if value is None:
                row[i] = self.baseline.get(col, {}).get("mean", 0.0)
                continue
            if isinstance(value, str):
                mapping = self.categorical_maps.get(col, {})
                row[i] = float(mapping.get(value, -1))
                continue
            try:
                row[i] = float(value)
            except (TypeError, ValueError):
                row[i] = self.baseline.get(col, {}).get("mean", 0.0)
        return row.reshape(1, -1)

    def deviations(self, vector: np.ndarray, limit: int = 6) -> list[dict]:
        """Rank features by (distance from normal) x (how much the model cares)."""
        scored = []
        flat = vector.ravel()
        for i, col in enumerate(self.features):
            stats = self.baseline.get(col)
            if not stats:
                continue
            std = stats["std"] or 1.0
            z = (float(flat[i]) - stats["mean"]) / std
            if abs(z) < 0.75:
                continue
            weight = abs(z) * (self.importance.get(col, 0.0) + 1e-4)
            scored.append({
                "feature": col,
                "label": friendly(col),
                "value": round(float(flat[i]), 3),
                "baseline": round(stats["mean"], 3),
                "z_score": round(z, 2),
                "weight": weight,
                "sentence": describe_deviation(col, float(flat[i]), stats["mean"], z),
            })
        scored.sort(key=lambda d: d["weight"], reverse=True)
        for d in scored:
            d.pop("weight")
        return scored[:limit]

    # -- the main entry point ---------------------------------------------

    def classify(
        self,
        sample: dict[str, Any],
        *,
        source_ip: str | None = None,
        asset: str | None = None,
        origin: str = "ingest",
        ground_truth: str | None = None,
    ) -> dict:
        t0 = time.perf_counter()
        vector = self.align(sample)

        with self._lock:
            probabilities = self.classifier.predict_proba(vector)[0]

        order = np.argsort(probabilities)[::-1]
        top_idx = int(order[0])
        attack_type = str(self.classes[top_idx])
        confidence = float(probabilities[top_idx])
        runner_up = (
            (str(self.classes[int(order[1])]), float(probabilities[int(order[1])]))
            if len(order) > 1 else None
        )

        novelty_score = None
        novel = False
        if self.novelty is not None and self.scaler is not None:
            novelty_score = float(self.novelty.score_samples(self.scaler.transform(vector))[0])
            novel = novelty_score < self.novelty_threshold

        prof = threat_profile(attack_type)
        devs = self.deviations(vector)
        narrative = summarise(
            attack_type=attack_type,
            profile=prof,
            confidence=confidence,
            novel=novel,
            deviations=devs,
            runner_up=runner_up,
        )

        needs_review = bool(novel or confidence < self.low_confidence)
        severity = prof["severity"]
        if novel and severity in ("info", "low"):
            # Traffic the model has never seen is never routine, whatever
            # nearest-neighbour label it happened to land on.
            severity = "medium"

        latency_ms = round((time.perf_counter() - t0) * 1000, 3)

        return {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip or sample.get("source_ip") or "unknown",
            "asset": asset,
            "origin": origin,
            "attack_type": attack_type,
            "family": prof["family"],
            "severity": severity,
            "mitre": prof["mitre"],
            "confidence": round(confidence, 4),
            "needs_review": needs_review,
            "novelty_score": round(novelty_score, 4) if novelty_score is not None else None,
            "is_novel": novel,
            "probabilities": {
                str(self.classes[i]): round(float(probabilities[i]), 4)
                for i in order[:5]
            },
            "explanation": devs,
            "narrative": narrative,
            "latency_ms": latency_ms,
            "ground_truth": ground_truth,
            "status": "new",
            "assignee": None,
            "notes": [],
        }

    # -- reporting ---------------------------------------------------------

    def model_card(self) -> dict:
        """Everything the dashboard's model page renders, in one payload."""
        m = self.metrics
        return {
            "algorithm": "Random Forest (supervised) + Isolation Forest (novelty)",
            "data_source": m.get("data_source"),
            "dataset_notes": m.get("dataset_notes", []),
            "trained_at": m.get("trained_at"),
            "rows_used": m.get("rows_used"),
            "train_size": m.get("train_size"),
            "test_size": m.get("test_size"),
            "n_features": m.get("n_features"),
            "classes": m.get("classes"),
            "class_counts": m.get("class_counts"),
            "accuracy": m.get("accuracy"),
            "balanced_accuracy": m.get("balanced_accuracy"),
            "macro_f1": m.get("macro_f1"),
            "weighted_f1": m.get("weighted_f1"),
            "cv_macro_f1": m.get("cv_macro_f1"),
            "per_class": m.get("per_class"),
            "confusion_matrix": m.get("confusion_matrix"),
            "family_report": m.get("family_report"),
            "family_confusion_matrix": m.get("family_confusion_matrix"),
            "families": self.metadata.get("families"),
            "attack_vs_normal": m.get("attack_vs_normal"),
            "baselines": m.get("baselines"),
            "latency": m.get("latency"),
            "hyperparameters": m.get("hyperparameters"),
            "feature_importances": [
                {**f, "label": friendly(f["feature"])}
                for f in m.get("feature_importances", [])[:15]
            ],
            "novelty": self.metadata.get("novelty"),
        }
