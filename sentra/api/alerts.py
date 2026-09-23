"""Alert retrieval, triage workflow and dashboard aggregates."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..runtime import Runtime, get_runtime
from ..schemas import AssignUpdate, NoteCreate, StatusUpdate
from ..security import require_api_key

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts")
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    family: str | None = None,
    status: str | None = None,
    attack_type: str | None = None,
    asset_id: str | None = None,
    needs_review: bool | None = None,
    search: str | None = None,
    rt: Runtime = Depends(get_runtime),
):
    """FR5 — the alert feed, with every filter the dashboard offers."""
    return rt.store.query(
        limit=limit, offset=offset, severity=severity, family=family,
        status=status, attack_type=attack_type, asset_id=asset_id,
        needs_review=needs_review, search=search,
    )


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, rt: Runtime = Depends(get_runtime)):
    alert = rt.store.get(alert_id)
    if not alert:
        raise HTTPException(404, "No alert with that id. It may have been cleared.")
    return alert


@router.patch("/alerts/{alert_id}/status", dependencies=[Depends(require_api_key)])
def set_status(alert_id: str, update: StatusUpdate, rt: Runtime = Depends(get_runtime)):
    """Move an alert through triage: new, investigating, contained, closed."""
    alert = rt.store.set_status(alert_id, update.status, update.actor)
    if not alert:
        raise HTTPException(404, "No alert with that id.")
    return alert


@router.patch("/alerts/{alert_id}/assignee", dependencies=[Depends(require_api_key)])
def set_assignee(alert_id: str, update: AssignUpdate, rt: Runtime = Depends(get_runtime)):
    alert = rt.store.assign(alert_id, update.assignee, update.actor)
    if not alert:
        raise HTTPException(404, "No alert with that id.")
    return alert


@router.post("/alerts/{alert_id}/notes", dependencies=[Depends(require_api_key)])
def add_note(alert_id: str, note: NoteCreate, rt: Runtime = Depends(get_runtime)):
    """Analyst working notes. These are what turn an alert into an incident record."""
    created = rt.store.add_note(alert_id, note.author, note.body)
    if not created:
        raise HTTPException(404, "No alert with that id.")
    return created


@router.delete("/alerts", dependencies=[Depends(require_api_key)])
def clear_alerts(rt: Runtime = Depends(get_runtime)):
    """Wipe the alert table. Logged to the audit trail, which is not wiped."""
    removed = rt.store.clear()
    return {"status": "cleared", "removed": removed}


@router.get("/stats")
def stats(window: int = Query(60, ge=1, le=1440), rt: Runtime = Depends(get_runtime)):
    """Rolling aggregates for the KPI row."""
    data = rt.store.stats(window_minutes=window)
    if rt.stream:
        data["stream"] = rt.stream.state()
    return data


@router.get("/timeline")
def timeline(
    minutes: int = Query(30, ge=5, le=720),
    buckets: int = Query(30, ge=6, le=120),
    rt: Runtime = Depends(get_runtime),
):
    """Bucketed event counts by severity, for the activity chart."""
    return {"minutes": minutes, "buckets": buckets, "series": rt.store.timeline(minutes, buckets)}
