"""
store.py
--------
Persistence. v1 kept alerts in a Python list capped at 500, which meant a
restart erased the entire audit trail -- the report calls this out as the
headline design flaw, so this is the fix.

SQLite is the right size for this system. It gives durability, real queries,
and an audit trail that survives a crash, with no server to install and no
extra dependency. The table layout keeps the hot filter columns (severity,
family, status, timestamp) as real columns and parks the rest of the alert in
a JSON blob, so adding a field to an alert never needs a migration.

Writes go through a single connection guarded by a lock. Under a dashboard's
load that is comfortably enough, and it avoids the "database is locked" errors
that come from sharing SQLite connections across threads.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    source_ip     TEXT,
    asset_id      TEXT,
    attack_type   TEXT NOT NULL,
    family        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    is_novel      INTEGER NOT NULL DEFAULT 0,
    needs_review  INTEGER NOT NULL DEFAULT 0,
    latency_ms    REAL,
    origin        TEXT,
    status        TEXT NOT NULL DEFAULT 'new',
    assignee      TEXT,
    ground_truth  TEXT,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sev      ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_family   ON alerts(family);

CREATE TABLE IF NOT EXISTS notes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id  TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author    TEXT NOT NULL,
    body      TEXT NOT NULL,
    created   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON notes(alert_id);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    created  TEXT NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created DESC);
"""

STATUSES = ["new", "investigating", "contained", "closed", "false_positive"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AlertStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- writes ------------------------------------------------------------

    def add(self, alert: dict) -> dict:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO alerts
                   (id, timestamp, source_ip, asset_id, attack_type, family, severity,
                    confidence, is_novel, needs_review, latency_ms, origin, status,
                    assignee, ground_truth, payload)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    alert["id"], alert["timestamp"], alert.get("source_ip"),
                    (alert.get("asset") or {}).get("id") if isinstance(alert.get("asset"), dict)
                    else alert.get("asset"),
                    alert["attack_type"], alert["family"], alert["severity"],
                    alert["confidence"], int(bool(alert.get("is_novel"))),
                    int(bool(alert.get("needs_review"))), alert.get("latency_ms"),
                    alert.get("origin"), alert.get("status", "new"),
                    alert.get("assignee"), alert.get("ground_truth"),
                    json.dumps(alert),
                ),
            )
            self._conn.commit()
        return alert

    def add_many(self, alerts: list[dict]) -> list[dict]:
        for a in alerts:
            self.add(a)
        return alerts

    def set_status(self, alert_id: str, status: str, actor: str = "analyst") -> dict | None:
        if status not in STATUSES:
            raise ValueError(f"Unknown status '{status}'. Use one of {STATUSES}.")
        alert = self.get(alert_id)
        if not alert:
            return None
        alert["status"] = status
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET status=?, payload=? WHERE id=?",
                (status, json.dumps(alert), alert_id),
            )
            self._conn.commit()
        self.log(actor, "status_change", alert_id, status)
        return alert

    def assign(self, alert_id: str, assignee: str | None, actor: str = "analyst") -> dict | None:
        alert = self.get(alert_id)
        if not alert:
            return None
        alert["assignee"] = assignee
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET assignee=?, payload=? WHERE id=?",
                (assignee, json.dumps(alert), alert_id),
            )
            self._conn.commit()
        self.log(actor, "assign", alert_id, assignee or "unassigned")
        return alert

    def add_note(self, alert_id: str, author: str, body: str) -> dict | None:
        if not self.get(alert_id):
            return None
        created = _now()
        with self._lock:
            self._conn.execute(
                "INSERT INTO notes (alert_id, author, body, created) VALUES (?,?,?,?)",
                (alert_id, author, body, created),
            )
            self._conn.commit()
        self.log(author, "note", alert_id, body[:120])
        return {"alert_id": alert_id, "author": author, "body": body, "created": created}

    def log(self, actor: str, action: str, target: str | None = None,
            detail: str | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit (created, actor, action, target, detail) VALUES (?,?,?,?,?)",
                (_now(), actor, action, target, detail),
            )
            self._conn.commit()

    def clear(self, actor: str = "analyst") -> int:
        with self._lock:
            n = self._conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            self._conn.execute("DELETE FROM notes")
            self._conn.execute("DELETE FROM alerts")
            self._conn.commit()
        self.log(actor, "clear_alerts", detail=f"{n} alerts removed")
        return n

    # -- reads -------------------------------------------------------------

    def get(self, alert_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM alerts WHERE id=?", (alert_id,)
            ).fetchone()
        if not row:
            return None
        alert = json.loads(row["payload"])
        alert["notes"] = self.notes(alert_id)
        return alert

    def notes(self, alert_id: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT author, body, created FROM notes WHERE alert_id=? ORDER BY id",
                (alert_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def query(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        family: str | None = None,
        status: str | None = None,
        attack_type: str | None = None,
        asset_id: str | None = None,
        needs_review: bool | None = None,
        search: str | None = None,
        since: str | None = None,
    ) -> dict:
        clauses, params = [], []
        if severity:
            clauses.append("severity=?"); params.append(severity)
        if family:
            clauses.append("family=?"); params.append(family)
        if status:
            clauses.append("status=?"); params.append(status)
        if attack_type:
            clauses.append("attack_type=?"); params.append(attack_type)
        if asset_id:
            clauses.append("asset_id=?"); params.append(asset_id)
        if needs_review is not None:
            clauses.append("needs_review=?"); params.append(int(needs_review))
        if since:
            clauses.append("timestamp >= ?"); params.append(since)
        if search:
            clauses.append("(source_ip LIKE ? OR attack_type LIKE ? OR asset_id LIKE ?)")
            params += [f"%{search}%"] * 3
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS c FROM alerts {where}", params
            ).fetchone()["c"]
            rows = self._conn.execute(
                f"SELECT payload FROM alerts {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [json.loads(r["payload"]) for r in rows],
        }

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]

    def stats(self, window_minutes: int = 60) -> dict:
        since = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
        with self._lock:
            rows = self._conn.execute(
                """SELECT severity, family, attack_type, asset_id, status,
                          confidence, latency_ms, is_novel, needs_review, timestamp
                   FROM alerts WHERE timestamp >= ?""",
                (since,),
            ).fetchall()
            all_time = self._conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
            open_count = self._conn.execute(
                "SELECT COUNT(*) AS c FROM alerts WHERE status IN ('new','investigating')"
            ).fetchone()["c"]

        by_sev = Counter(r["severity"] for r in rows)
        by_family = Counter(r["family"] for r in rows)
        by_type = Counter(r["attack_type"] for r in rows)
        by_asset = Counter(r["asset_id"] for r in rows if r["asset_id"])
        by_status = Counter(r["status"] for r in rows)
        latencies = [r["latency_ms"] for r in rows if r["latency_ms"] is not None]

        return {
            "window_minutes": window_minutes,
            "events_in_window": len(rows),
            "events_all_time": all_time,
            "open_alerts": open_count,
            "by_severity": dict(by_sev),
            "by_family": dict(by_family),
            "by_attack_type": dict(by_type),
            "by_asset": dict(by_asset),
            "by_status": dict(by_status),
            "novel_count": sum(1 for r in rows if r["is_novel"]),
            "needs_review_count": sum(1 for r in rows if r["needs_review"]),
            "attack_count": sum(1 for r in rows if r["attack_type"] != "Normal"),
            "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
            "avg_confidence": (
                round(sum(r["confidence"] for r in rows) / len(rows), 4) if rows else 0.0
            ),
        }

    def timeline(self, minutes: int = 30, buckets: int = 30) -> list[dict]:
        """Event counts per time bucket, for the dashboard's activity chart."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
        span = (end - start) / buckets
        with self._lock:
            rows = self._conn.execute(
                "SELECT timestamp, severity FROM alerts WHERE timestamp >= ?",
                (start.isoformat(),),
            ).fetchall()

        series = [
            {"t": (start + span * i).isoformat(), "total": 0,
             "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for i in range(buckets)
        ]
        for r in rows:
            try:
                ts = datetime.fromisoformat(r["timestamp"])
            except ValueError:
                continue
            idx = int((ts - start) / span)
            if 0 <= idx < buckets:
                series[idx]["total"] += 1
                series[idx][r["severity"]] = series[idx].get(r["severity"], 0) + 1
        return series

    def audit(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT created, actor, action, target, detail FROM audit "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
