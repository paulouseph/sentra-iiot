"""
streamer.py
-----------
Two things live here: the replay pool, and the background task that feeds it
through the engine so the dashboard has something to show.

Replay matters for honesty. v1's dashboard was driven by the same synthetic
generator the model was trained on, so the demo could never disagree with the
model -- an impressive-looking loop that proved nothing. Here the pool is
built from held-out Edge-IIoTset rows the classifier has never seen, and each
replayed event keeps its true label. The dashboard can therefore show a live
running accuracy, and when the model gets one wrong, you watch it happen.
"""
from __future__ import annotations

import asyncio
import logging
import random
from pathlib import Path

import pandas as pd
from fastapi import WebSocket

from . import assets
from .config import get_settings
from .engine import DetectionEngine
from .store import AlertStore

log = logging.getLogger(__name__)


class ReplayPool:
    """Held-out real samples, indexed by their true label."""

    def __init__(self, path: Path):
        self.path = path
        self.by_label: dict[str, pd.DataFrame] = {}
        self.available = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            log.warning("No replay pool at %s -- simulation will use jittered baselines.", self.path)
            return
        df = pd.read_csv(self.path)
        if "__label" not in df.columns:
            log.warning("Replay pool has no __label column; ignoring it.")
            return
        for label, group in df.groupby("__label"):
            self.by_label[str(label)] = group.drop(columns=["__label"]).reset_index(drop=True)
        self.available = True
        log.info(
            "Replay pool ready: %d rows across %d classes.",
            sum(len(g) for g in self.by_label.values()), len(self.by_label),
        )

    @property
    def labels(self) -> list[str]:
        return sorted(self.by_label)

    @property
    def attack_labels(self) -> list[str]:
        return [l for l in self.labels if l != "Normal"]

    def draw(self, label: str, n: int = 1) -> list[tuple[dict, str]]:
        """Return n (features, true_label) pairs for a class."""
        frame = self.by_label.get(label)
        if frame is None or frame.empty:
            return []
        rows = frame.sample(min(n, len(frame)), replace=n > len(frame))
        return [(row.to_dict(), label) for _, row in rows.iterrows()]

    def draw_weighted(self, attack_ratio: float) -> tuple[dict, str] | None:
        """One sample, mostly normal, occasionally an attack -- like a real plant."""
        if not self.available:
            return None
        if random.random() < attack_ratio and self.attack_labels:
            label = random.choice(self.attack_labels)
        else:
            label = "Normal" if "Normal" in self.by_label else random.choice(self.labels)
        drawn = self.draw(label, 1)
        return drawn[0] if drawn else None


class ConnectionManager:
    """Tracks dashboard WebSocket clients and fans events out to them."""

    def __init__(self) -> None:
        self.active: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self.active.add(ws)
        log.info("Dashboard connected (%d open).", len(self.active))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self.active.discard(ws)

    async def broadcast(self, message: dict) -> None:
        if not self.active:
            return
        async with self._lock:
            targets = list(self.active)
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self.active.discard(ws)

    @property
    def count(self) -> int:
        return len(self.active)


class LiveStream:
    """Background producer. Can be paused and re-tuned from the dashboard."""

    def __init__(self, engine: DetectionEngine, store: AlertStore,
                 pool: ReplayPool, manager: ConnectionManager):
        self.engine = engine
        self.store = store
        self.pool = pool
        self.manager = manager
        settings = get_settings()
        self.interval_ms = settings.stream_interval_ms
        self.attack_ratio = settings.stream_attack_ratio
        self.running = settings.stream_enabled
        self._task: asyncio.Task | None = None
        self.emitted = 0
        self.correct = 0

    # -- control -----------------------------------------------------------

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def configure(self, *, running: bool | None = None,
                  interval_ms: int | None = None,
                  attack_ratio: float | None = None) -> dict:
        if running is not None:
            self.running = running
        if interval_ms is not None:
            self.interval_ms = max(200, min(interval_ms, 10_000))
        if attack_ratio is not None:
            self.attack_ratio = max(0.0, min(attack_ratio, 1.0))
        return self.state()

    def state(self) -> dict:
        return {
            "running": self.running,
            "interval_ms": self.interval_ms,
            "attack_ratio": round(self.attack_ratio, 3),
            "replay_available": self.pool.available,
            "emitted": self.emitted,
            "live_accuracy": round(self.correct / self.emitted, 4) if self.emitted else None,
            "clients": self.manager.count,
        }

    # -- production --------------------------------------------------------

    def produce(self) -> dict | None:
        drawn = self.pool.draw_weighted(self.attack_ratio)
        if drawn is None:
            return None
        features, truth = drawn
        asset = assets.for_attack(truth, seed=f"{truth}{random.randint(0, 999)}")
        alert = self.engine.classify(
            features,
            source_ip=asset.ip,
            asset=asset.dict(),
            origin="live",
            ground_truth=truth,
        )
        self.emitted += 1
        if alert["attack_type"] == truth:
            self.correct += 1
        self.store.add(alert)
        return alert

    async def _loop(self) -> None:
        log.info("Live stream loop started.")
        while True:
            try:
                if self.running:
                    alert = await asyncio.to_thread(self.produce)
                    if alert:
                        await self.manager.broadcast({"type": "alert", "data": alert})
                await asyncio.sleep(self.interval_ms / 1000)
            except asyncio.CancelledError:
                log.info("Live stream loop cancelled.")
                raise
            except Exception:
                log.exception("Live stream iteration failed; continuing.")
                await asyncio.sleep(2)
