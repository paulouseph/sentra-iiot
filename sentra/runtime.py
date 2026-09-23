"""
runtime.py
----------
Holds the long-lived objects -- engine, store, replay pool, live stream -- and
hands them to routers through FastAPI dependencies.

The alternative would be module-level globals, which make the whole thing
untestable: you cannot point the app at a temporary database without editing
source. Building a Runtime at startup and injecting it means the test suite
spins up a throwaway instance per test, and everything else keeps working.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, Request

from .config import Settings, get_settings
from .engine import DetectionEngine, ModelNotTrained
from .store import AlertStore
from .streamer import ConnectionManager, LiveStream, ReplayPool

log = logging.getLogger(__name__)

VERSION = "2.0.0"


@dataclass
class Runtime:
    settings: Settings
    store: AlertStore
    engine: DetectionEngine | None
    pool: ReplayPool
    manager: ConnectionManager
    stream: LiveStream | None
    load_error: str | None = None

    @property
    def ready(self) -> bool:
        return self.engine is not None

    def require_engine(self) -> DetectionEngine:
        if self.engine is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    self.load_error
                    or "The detection model is not loaded. Run: python -m sentra.ml.train"
                ),
            )
        return self.engine

    def shutdown(self) -> None:
        self.store.close()


def build(settings: Settings | None = None, db_path: Path | None = None) -> Runtime:
    settings = settings or get_settings()
    store = AlertStore(db_path or settings.db_path)
    manager = ConnectionManager()
    pool = ReplayPool(settings.artifact_dir / "replay.csv")

    engine: DetectionEngine | None = None
    load_error: str | None = None
    try:
        engine = DetectionEngine(settings.artifact_dir)
    except ModelNotTrained as exc:
        load_error = str(exc)
        log.error("%s", exc)

    stream = LiveStream(engine, store, pool, manager) if engine else None
    return Runtime(settings, store, engine, pool, manager, stream, load_error)


def get_runtime(request: Request) -> Runtime:
    return request.app.state.runtime
