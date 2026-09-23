"""
config.py
---------
Every tunable lives here and can be overridden from the environment or a
.env file, so the same code runs on a laptop, in a lab VM, and in CI without
edits. See .env.example for the full list.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.getenv("SENTRA_ENV_FILE", ROOT / ".env"),
        env_prefix="SENTRA_",
        extra="ignore",
    )

    # --- paths -------------------------------------------------------------
    data_dir: Path = ROOT / "data"
    artifact_dir: Path = ROOT / "sentra" / "ml" / "artifacts"
    frontend_dir: Path = ROOT / "frontend"
    db_path: Path = ROOT / "data" / "sentra.db"

    # --- dataset -----------------------------------------------------------
    # Edge-IIoTset ships two CSVs. ML-EdgeIIoT-dataset.csv (~157k rows) is the
    # pre-sampled one and trains in about a minute. DNN-EdgeIIoT-dataset.csv
    # (~2.2M rows) is the full corpus; set max_rows to cap memory use.
    dataset_file: str = "ML-EdgeIIoT-dataset.csv"
    max_rows: int | None = None
    test_size: float = 0.2
    random_state: int = 42

    # --- model -------------------------------------------------------------
    n_estimators: int = 300
    max_depth: int = 24
    min_samples_leaf: int = 2
    novelty_contamination: float = 0.02
    # Below this confidence the engine refuses to commit to a label and marks
    # the event "needs a human". Honest uncertainty beats a confident guess.
    low_confidence_threshold: float = 0.55

    # --- live stream -------------------------------------------------------
    stream_enabled: bool = True
    stream_interval_ms: int = 1400
    stream_attack_ratio: float = 0.18  # share of replayed events that are attacks

    # --- api ---------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: str = "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5500"
    # Mutating routes (simulate, clear, incident updates) require this header:
    #   X-API-Key: <api_key>
    # Set to "" to disable auth entirely for a classroom demo.
    api_key: str = "sentra-dev-key"
    max_alerts_in_memory: int = 2000

    @property
    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def dataset_path(self) -> Path:
        return self.data_dir / self.dataset_file


@lru_cache
def get_settings() -> Settings:
    return Settings()
