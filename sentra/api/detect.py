"""Classification, simulation and the live WebSocket channel."""
from __future__ import annotations

import asyncio
import logging
import random

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect

from .. import assets as asset_registry
from ..runtime import Runtime, get_runtime
from ..schemas import SimulationRequest, StreamControl, TrafficSample
from ..security import limit_simulations, require_api_key
from ..taxonomy import ATTACK_TYPES

log = logging.getLogger(__name__)
router = APIRouter(tags=["detection"])


@router.post("/api/predict")
def predict(sample: TrafficSample, rt: Runtime = Depends(get_runtime)):
    """Classify one flow. Reads are open; this does not mutate stored state."""
    engine = rt.require_engine()
    asset = asset_registry.BY_ID.get(sample.asset_id or "") or (
        asset_registry.for_ip(sample.source_ip or "")
    )
    alert = engine.classify(
        sample.features,
        source_ip=sample.source_ip,
        asset=asset.dict() if asset else None,
        origin="api",
    )
    rt.store.add(alert)
    return alert


def _synthesise(engine, attack_type: str, n: int) -> list[dict]:
    """Fallback when the replay pool has no rows for a class.

    Jitters the normal-traffic baseline rather than inventing a distribution,
    so the result is clearly a stand-in and never pretends to be real capture.
    """
    rows = []
    rng = np.random.default_rng()
    for _ in range(n):
        row = {}
        for col, stats in engine.baseline.items():
            row[col] = float(max(0.0, rng.normal(stats["mean"], stats["std"] * 1.6)))
        rows.append(row)
    return rows


@router.post(
    "/api/simulate",
    dependencies=[Depends(require_api_key), Depends(limit_simulations)],
)
async def simulate(req: SimulationRequest, rt: Runtime = Depends(get_runtime)):
    """FR4 — inject a controlled burst of traffic for a drill.

    Samples are drawn from held-out Edge-IIoTset rows the model never saw in
    training, so a drill is a genuine test rather than a replay of memorised
    data. Requires an API key and is rate limited.
    """
    engine = rt.require_engine()
    if req.attack_type not in ATTACK_TYPES:
        raise HTTPException(
            400,
            f"'{req.attack_type}' is not a known class. Choose one of: {', '.join(ATTACK_TYPES)}",
        )

    drawn = rt.pool.draw(req.attack_type, req.count)
    if drawn:
        samples = [(features, truth) for features, truth in drawn]
        real = True
    else:
        samples = [(f, req.attack_type) for f in _synthesise(engine, req.attack_type, req.count)]
        real = False

    alerts = []
    for features, truth in samples:
        asset = (
            asset_registry.BY_ID.get(req.asset_id or "")
            or asset_registry.for_attack(req.attack_type, seed=str(random.random()))
        )
        alert = engine.classify(
            features,
            source_ip=asset.ip,
            asset=asset.dict(),
            origin="simulation",
            ground_truth=truth,
        )
        rt.store.add(alert)
        alerts.append(alert)
        await rt.manager.broadcast({"type": "alert", "data": alert})

    rt.store.log("operator", "simulate", req.attack_type, f"{len(alerts)} flows")
    detected = sum(1 for a in alerts if a["attack_type"] == req.attack_type)

    return {
        "attack_type": req.attack_type,
        "requested": req.count,
        "generated": len(alerts),
        "source": (
            f"held-out {engine.metadata.get('data_source', 'training')} rows"
            if real else "baseline jitter (no held-out rows for this class)"
        ),
        "detected_correctly": detected,
        "detection_rate": round(detected / len(alerts), 3) if alerts else 0.0,
        "alerts": alerts,
    }


@router.get("/api/stream")
def stream_state(rt: Runtime = Depends(get_runtime)):
    if not rt.stream:
        return {"running": False, "reason": "model not loaded"}
    return rt.stream.state()


@router.post("/api/stream", dependencies=[Depends(require_api_key)])
def stream_control(ctrl: StreamControl, rt: Runtime = Depends(get_runtime)):
    """Pause, resume or re-tune the live feed from the dashboard."""
    if not rt.stream:
        raise HTTPException(503, "The live stream needs a trained model.")
    state = rt.stream.configure(
        running=ctrl.running,
        interval_ms=ctrl.interval_ms,
        attack_ratio=ctrl.attack_ratio,
    )
    rt.store.log("operator", "stream_control", detail=str(state))
    return state


@router.websocket("/ws/live")
async def live(ws: WebSocket):
    """Push channel for the dashboard.

    v1 shipped this endpoint but the frontend never used it, polling every
    four seconds instead. The v2 dashboard connects here and falls back to
    polling only if the socket cannot be established.
    """
    rt: Runtime = ws.app.state.runtime
    await rt.manager.connect(ws)
    try:
        await ws.send_json({
            "type": "hello",
            "data": {
                "stream": rt.stream.state() if rt.stream else {"running": False},
                "stored": rt.store.count(),
            },
        })
        while True:
            # Clients send periodic pings; we answer so intermediate proxies
            # keep the connection open.
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        raise
    except Exception:
        log.debug("WebSocket closed unexpectedly", exc_info=True)
    finally:
        await rt.manager.disconnect(ws)
