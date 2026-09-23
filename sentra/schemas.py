"""
schemas.py
----------
Request and response contracts. FastAPI turns these into both runtime
validation and the OpenAPI documentation at /docs, so the field descriptions
below are what another developer reads when integrating -- worth writing well.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Status = Literal["new", "investigating", "contained", "closed", "false_positive"]


class TrafficSample(BaseModel):
    """One network flow to classify.

    Features are passed as a free-form mapping keyed by Edge-IIoTset column
    name. Anything the model expects but you omit falls back to the
    normal-traffic baseline rather than zero, so partial captures still work.
    """

    features: dict[str, Any] = Field(
        ...,
        description="Edge-IIoTset feature values, e.g. {'tcp.len': 1240, 'http.content_length': 640}",
    )
    source_ip: str | None = Field(None, description="Observed source address")
    asset_id: str | None = Field(None, description="Asset this flow belongs to, if known")

    model_config = {
        "json_schema_extra": {
            "example": {
                "features": {"tcp.len": 1240, "tcp.connection.syn": 44, "http.content_length": 0},
                "source_ip": "10.0.1.11",
            }
        }
    }


class SimulationRequest(BaseModel):
    attack_type: str = Field(..., description="One of the 15 Edge-IIoTset classes")
    count: int = Field(5, ge=1, le=50, description="How many flows to inject")
    asset_id: str | None = Field(None, description="Target a specific asset")


class StatusUpdate(BaseModel):
    status: Status
    actor: str = Field("analyst", max_length=64)


class AssignUpdate(BaseModel):
    assignee: str | None = Field(None, max_length=64)
    actor: str = Field("analyst", max_length=64)


class NoteCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=2000)
    author: str = Field("analyst", max_length=64)


class StreamControl(BaseModel):
    running: bool | None = None
    interval_ms: int | None = Field(None, ge=200, le=10_000)
    attack_ratio: float | None = Field(None, ge=0.0, le=1.0)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    data_source: str | None
    classes: int
    features: int
    alerts_stored: int
    stream: dict
    version: str
