"""System and reference endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from .. import assets as asset_registry
from ..runtime import VERSION, Runtime, get_runtime
from ..schemas import HealthResponse
from ..taxonomy import ATTACK_TYPES, FAMILIES, PROFILES, SEVERITIES, SEVERITY_COLOURS

router = APIRouter(tags=["system"])


@router.get("/api/health", response_model=HealthResponse)
def health(rt: Runtime = Depends(get_runtime)):
    """Liveness plus enough detail for the dashboard's status pill."""
    engine = rt.engine
    return HealthResponse(
        status="ok" if rt.ready else "degraded",
        model_loaded=rt.ready,
        data_source=engine.metadata.get("data_source") if engine else None,
        classes=len(engine.classes) if engine else 0,
        features=len(engine.features) if engine else 0,
        alerts_stored=rt.store.count(),
        stream=rt.stream.state() if rt.stream else {"running": False},
        version=VERSION,
    )


@router.get("/api/model/card")
def model_card(rt: Runtime = Depends(get_runtime)):
    """Full evaluation report: metrics, confusion matrices, baselines, latency."""
    return rt.require_engine().model_card()


@router.post("/api/model/reload")
def reload_model(rt: Runtime = Depends(get_runtime)):
    """Pick up freshly trained artifacts without restarting the server."""
    rt.require_engine().reload()
    rt.store.log("operator", "model_reload")
    return {"status": "reloaded", "trained_at": rt.engine.metrics.get("trained_at")}


@router.get("/api/assets")
def list_assets(rt: Runtime = Depends(get_runtime)):
    """The plant inventory, each asset carrying its current alert counts."""
    stats = rt.store.stats(window_minutes=60)
    by_asset = stats["by_asset"]
    items = []
    for asset in asset_registry.inventory():
        items.append({**asset, "events_last_hour": by_asset.get(asset["id"], 0)})
    return {"assets": items, "zones": sorted({a["zone"] for a in items})}


@router.get("/api/taxonomy")
def taxonomy():
    """Everything the UI needs to label, colour and explain a classification."""
    return {
        "attack_types": ATTACK_TYPES,
        "families": FAMILIES,
        "severities": SEVERITIES,
        "severity_colours": SEVERITY_COLOURS,
        "profiles": PROFILES,
    }


@router.get("/api/audit")
def audit(limit: int = 50, rt: Runtime = Depends(get_runtime)):
    """Who did what. Persisted, so it survives a restart."""
    return {"entries": rt.store.audit(limit=limit)}
