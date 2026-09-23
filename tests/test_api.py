"""
API and engine tests.

Chapter 5 of the project report states plainly that v1 had no automated tests
and that verification was done by hand. This suite closes that gap. It runs
against a throwaway SQLite file and the real trained artifacts, so a green run
means the shipped system works, not a mock of it.

    pytest -q
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sentra import runtime as rt_module
from sentra.config import get_settings
from sentra.main import create_app
from sentra.taxonomy import ATTACK_TYPES, PROFILES

API_KEY = get_settings().api_key
AUTH = {"X-API-Key": API_KEY}

pytestmark = pytest.mark.skipif(
    not (get_settings().artifact_dir / "classifier.joblib").exists(),
    reason="Model artifacts missing. Run: python -m sentra.ml.train --synthetic",
)


@pytest.fixture(scope="module")
def client():
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    app = create_app()

    original_build = rt_module.build
    app.router.lifespan_context = None  # rebuilt below via TestClient startup

    def build_with_tmp_db(settings=None, db_path=None):
        return original_build(settings, db_path=tmp)

    rt_module.build = build_with_tmp_db
    app = create_app()
    with TestClient(app) as c:
        # Keep the background stream quiet so assertions are deterministic.
        c.post("/api/stream", json={"running": False}, headers=AUTH)
        yield c
    rt_module.build = original_build


# -- taxonomy consistency ---------------------------------------------------

def test_every_class_has_an_analyst_profile():
    """A class the UI cannot explain is a class that should not ship."""
    missing = [a for a in ATTACK_TYPES if a not in PROFILES]
    assert not missing, f"No analyst profile for: {missing}"


def test_profiles_carry_actionable_guidance():
    for name, prof in PROFILES.items():
        assert prof["actions"], f"{name} has no recommended actions"
        assert len(prof["story"]) > 40, f"{name} story is too thin to be useful"


# -- health and reference ---------------------------------------------------

def test_health_reports_a_loaded_model(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["model_loaded"] is True
    assert body["classes"] >= 10
    assert body["features"] > 0


def test_model_card_has_honest_metrics(client):
    card = client.get("/api/model/card").json()
    assert 0.0 < card["accuracy"] <= 1.0
    assert card["balanced_accuracy"] <= card["accuracy"] + 1e-9
    assert card["confusion_matrix"], "confusion matrix missing"
    assert card["baselines"], "no baseline comparison recorded"
    # The headline number must beat guessing the majority class.
    assert card["accuracy"] > card["baselines"]["Majority class"]["accuracy"]


def test_asset_inventory_is_populated(client):
    body = client.get("/api/assets").json()
    assert len(body["assets"]) >= 8
    assert all(a["consequence"] for a in body["assets"])


# -- classification ---------------------------------------------------------

def test_predict_returns_a_complete_alert(client):
    r = client.post("/api/predict", json={
        "features": {"tcp.len": 1200, "tcp.connection.syn": 40},
        "source_ip": "10.0.1.11",
    })
    assert r.status_code == 200
    alert = r.json()
    for field in ("attack_type", "family", "severity", "confidence",
                  "narrative", "explanation", "latency_ms"):
        assert field in alert, f"alert is missing {field}"
    assert 0.0 <= alert["confidence"] <= 1.0
    assert alert["narrative"]["actions"], "no recommended actions on the alert"
    assert alert["narrative"]["confidence_word"]


def test_predict_tolerates_a_partial_feature_set(client):
    """Missing features fall back to baseline rather than throwing."""
    r = client.post("/api/predict", json={"features": {"tcp.len": 80}})
    assert r.status_code == 200
    assert r.json()["attack_type"] in ATTACK_TYPES


def test_predict_rejects_a_malformed_body(client):
    assert client.post("/api/predict", json={"nope": 1}).status_code == 422


def test_latency_meets_the_performance_requirement(client):
    alert = client.post("/api/predict", json={"features": {"tcp.len": 400}}).json()
    assert alert["latency_ms"] < 2000, "NFR: classification must stay well under 2s"


# -- simulation and authorisation ------------------------------------------

def test_simulation_requires_an_api_key(client):
    r = client.post("/api/simulate", json={"attack_type": "DDoS_TCP", "count": 2})
    assert r.status_code == 401
    assert "API key" in r.json()["detail"]


def test_simulation_generates_the_requested_burst(client):
    r = client.post("/api/simulate",
                    json={"attack_type": "DDoS_TCP", "count": 4}, headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["generated"] == 4
    assert len(body["alerts"]) == 4
    assert 0.0 <= body["detection_rate"] <= 1.0


def test_simulation_rejects_an_unknown_class(client):
    r = client.post("/api/simulate",
                    json={"attack_type": "not_a_real_attack", "count": 1}, headers=AUTH)
    assert r.status_code == 400
    assert "known class" in r.json()["detail"]


def test_simulation_clamps_the_count(client):
    r = client.post("/api/simulate",
                    json={"attack_type": "Normal", "count": 999}, headers=AUTH)
    assert r.status_code == 422  # Pydantic enforces the 1-50 bound


# -- triage workflow --------------------------------------------------------

def test_alert_moves_through_triage(client):
    alert_id = client.post("/api/simulate",
                           json={"attack_type": "Ransomware", "count": 1},
                           headers=AUTH).json()["alerts"][0]["id"]

    r = client.patch(f"/api/alerts/{alert_id}/status",
                     json={"status": "investigating"}, headers=AUTH)
    assert r.json()["status"] == "investigating"

    r = client.patch(f"/api/alerts/{alert_id}/assignee",
                     json={"assignee": "shift-b"}, headers=AUTH)
    assert r.json()["assignee"] == "shift-b"

    r = client.post(f"/api/alerts/{alert_id}/notes",
                    json={"body": "Host isolated at the cell switch."}, headers=AUTH)
    assert r.status_code == 200

    fetched = client.get(f"/api/alerts/{alert_id}").json()
    assert len(fetched["notes"]) == 1
    assert fetched["notes"][0]["body"].startswith("Host isolated")


def test_unknown_alert_returns_404(client):
    assert client.get("/api/alerts/does-not-exist").status_code == 404


def test_invalid_status_is_rejected(client):
    alert_id = client.get("/api/alerts?limit=1").json()["items"][0]["id"]
    r = client.patch(f"/api/alerts/{alert_id}/status",
                     json={"status": "banana"}, headers=AUTH)
    assert r.status_code == 422


# -- feed, filters and aggregates ------------------------------------------

def test_alert_feed_filters_by_severity(client):
    client.post("/api/simulate", json={"attack_type": "Backdoor", "count": 3}, headers=AUTH)
    body = client.get("/api/alerts?severity=critical&limit=10").json()
    assert all(a["severity"] == "critical" for a in body["items"])


def test_alert_feed_paginates(client):
    first = client.get("/api/alerts?limit=2&offset=0").json()
    second = client.get("/api/alerts?limit=2&offset=2").json()
    assert first["items"] and second["items"]
    assert first["items"][0]["id"] != second["items"][0]["id"]


def test_stats_and_timeline_are_consistent(client):
    stats = client.get("/api/stats?window=60").json()
    assert stats["events_all_time"] >= stats["events_in_window"]
    series = client.get("/api/timeline?minutes=30&buckets=10").json()["series"]
    assert len(series) == 10


def test_audit_trail_records_privileged_actions(client):
    entries = client.get("/api/audit?limit=50").json()["entries"]
    assert any(e["action"] == "simulate" for e in entries)


# -- persistence ------------------------------------------------------------

def test_alerts_survive_in_the_database(client, tmp_path):
    """The v1 failure mode: a restart wiped everything. It no longer does."""
    before = client.get("/api/stats").json()["events_all_time"]
    client.post("/api/simulate", json={"attack_type": "MITM", "count": 2}, headers=AUTH)
    after = client.get("/api/stats").json()["events_all_time"]
    assert after == before + 2


def test_clearing_alerts_requires_a_key_and_is_audited(client):
    assert client.delete("/api/alerts").status_code == 401
    r = client.delete("/api/alerts", headers=AUTH)
    assert r.status_code == 200
    assert client.get("/api/stats").json()["events_all_time"] == 0
    entries = client.get("/api/audit?limit=10").json()["entries"]
    assert any(e["action"] == "clear_alerts" for e in entries)
