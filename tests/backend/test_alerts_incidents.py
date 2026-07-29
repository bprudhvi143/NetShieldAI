import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from app.main import app
from app.db.postgres import SessionLocal
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.alert_history import AlertHistory
from app.models.incident_history import IncidentHistory
from app.models.user import User
from app.config.settings import settings

@pytest.fixture(scope="module")
def client():
    # Make sure env is set so import of app config works
    os.environ["PYTHONPATH"] = "backend"
    with TestClient(app) as c:
        yield c

@pytest.fixture(scope="module")
def auth_headers(client):
    # Log in as admin
    admin_login_res = client.post(
        "/api/v1/auth/login-json",
        json={"email": "admin@netshield.ai", "password": "AdminNetShield123!"}
    )
    assert admin_login_res.status_code == 200
    admin_token = admin_login_res.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Log in as analyst
    analyst_login_res = client.post(
        "/api/v1/auth/login-json",
        json={"email": "analyst@netshield.ai", "password": "AnalystNetShield123!"}
    )
    assert analyst_login_res.status_code == 200
    analyst_token = analyst_login_res.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    return {
        "admin": admin_headers,
        "analyst": analyst_headers
    }

@pytest.fixture(autouse=True)
def cleanup_db():
    db = SessionLocal()
    try:
        # Clean up existing tables to ensure isolation
        db.execute(delete(AlertHistory))
        db.execute(delete(IncidentHistory))
        db.execute(delete(Alert))
        db.execute(delete(Incident))
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.execute(delete(AlertHistory))
        db.execute(delete(IncidentHistory))
        db.execute(delete(Alert))
        db.execute(delete(Incident))
        db.commit()
    finally:
        db.close()

# Helper templates for Phase 5 Assessment
def get_mock_assessment(
    dataset="cicids2017",
    signal_status="confirmed_attack",
    threat_score=85.0,
    risk_level="High",
    severity="High",
    priority="P2",
    anomaly_detected=True,
    anomaly_score=0.9,
    is_attack=True,
    attack_probability=0.95,
    predicted_class="DDoS",
    confidence=0.92
):
    return {
        "dataset": dataset,
        "detection": {
            "status": "Attack" if is_attack else ("Suspicious" if anomaly_detected else "Normal"),
            "anomaly_detected": anomaly_detected,
            "anomaly_score": anomaly_score
        },
        "intrusion_prediction": {
            "is_attack": is_attack,
            "attack_probability": attack_probability,
            "normal_probability": 1.0 - attack_probability,
            "confidence": 0.90
        },
        "attack_classification": {
            "classification_status": "performed" if is_attack else "not_run",
            "predicted_class": predicted_class if is_attack else None,
            "confidence": confidence if is_attack else None,
            "class_probabilities": {predicted_class: confidence} if is_attack else {}
        },
        "risk": {
            "threat_score": threat_score,
            "risk_level": risk_level,
            "severity": severity,
            "impact_level": severity,
            "priority": priority,
            "score_breakdown": {"anomaly": 40.0, "intrusion": 45.0}
        },
        "signal_status": signal_status,
        "reasons": ["High anomaly score and confirmed signature match."]
    }

def test_alert_generation_policy(client, auth_headers):
    # 1. Normal traffic should NOT trigger alert
    normal_payload = {
        "event_id": "evt-normal-1",
        "assessment": get_mock_assessment(
            signal_status="normal", is_attack=False, anomaly_detected=False, threat_score=5.0, risk_level="Low", severity="Low", priority="P4"
        ),
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "protocol": "TCP"
    }
    res = client.post("/api/v1/alerts/evaluate", json=normal_payload, headers=auth_headers["analyst"])
    assert res.status_code == 201
    assert res.json() is None

    # 2. Confirmed Attack SHOULD trigger alert
    attack_payload = {
        "event_id": "evt-attack-1",
        "assessment": get_mock_assessment(),
        "source_ip": "192.168.1.101",
        "destination_ip": "10.0.0.2",
        "protocol": "TCP"
    }
    res = client.post("/api/v1/alerts/evaluate", json=attack_payload, headers=auth_headers["analyst"])
    assert res.status_code == 201
    alert_data = res.json()
    assert alert_data is not None
    assert alert_data["event_id"] == "evt-attack-1"
    assert alert_data["status"] == "NEW"
    assert alert_data["severity"] == "High"
    assert alert_data["priority"] == "P2"
    assert alert_data["alert_type"] == "CONFIRMED_ATTACK"

    # 3. Anomaly-only behavior based on settings
    # Default ALERT_ON_ANOMALY_ONLY is False (see settings.py)
    anomaly_payload = {
        "event_id": "evt-anomaly-1",
        "assessment": get_mock_assessment(
            signal_status="anomaly_only", is_attack=False, anomaly_detected=True, threat_score=35.0, risk_level="Medium", severity="Medium", priority="P3"
        ),
        "source_ip": "192.168.1.102",
        "destination_ip": "10.0.0.3",
        "protocol": "UDP"
    }
    res = client.post("/api/v1/alerts/evaluate", json=anomaly_payload, headers=auth_headers["analyst"])
    assert res.status_code == 201
    assert res.json() is None

    # Temporarily override ALERT_ON_ANOMALY_ONLY to True
    original_anomaly_only = settings.ALERT_ON_ANOMALY_ONLY
    settings.ALERT_ON_ANOMALY_ONLY = True
    try:
        res = client.post("/api/v1/alerts/evaluate", json=anomaly_payload, headers=auth_headers["analyst"])
        assert res.status_code == 201
        alert_data = res.json()
        assert alert_data is not None
        assert alert_data["event_id"] == "evt-anomaly-1"
        assert alert_data["alert_type"] == "ANOMALY_DETECTED"
    finally:
        settings.ALERT_ON_ANOMALY_ONLY = original_anomaly_only

def test_event_id_idempotency(client, auth_headers):
    payload = {
        "event_id": "evt-idemp-1",
        "assessment": get_mock_assessment(),
        "source_ip": "192.168.1.103",
        "destination_ip": "10.0.0.4"
    }

    # First execution creates alert
    res1 = client.post("/api/v1/alerts/evaluate", json=payload, headers=auth_headers["analyst"])
    assert res1.status_code == 201
    alert1 = res1.json()

    # Second execution with same event_id returns the identical alert
    res2 = client.post("/api/v1/alerts/evaluate", json=payload, headers=auth_headers["analyst"])
    assert res2.status_code == 201
    alert2 = res2.json()

    assert alert1["id"] == alert2["id"]
    assert alert1["repeat_count"] == alert2["repeat_count"] == 1

def test_alert_deduplication(client, auth_headers):
    # Post first event
    payload1 = {
        "event_id": "evt-dedup-1",
        "assessment": get_mock_assessment(),
        "source_ip": "192.168.1.104",
        "destination_ip": "10.0.0.5",
        "protocol": "TCP"
    }
    res1 = client.post("/api/v1/alerts/evaluate", json=payload1, headers=auth_headers["analyst"])
    assert res1.status_code == 201
    alert1 = res1.json()

    # Post second event with different event_id but identical deduplication fingerprint
    payload2 = {
        "event_id": "evt-dedup-2",
        "assessment": get_mock_assessment(),
        "source_ip": "192.168.1.104",
        "destination_ip": "10.0.0.5",
        "protocol": "TCP"
    }
    res2 = client.post("/api/v1/alerts/evaluate", json=payload2, headers=auth_headers["analyst"])
    assert res2.status_code == 201
    alert2 = res2.json()

    assert alert1["id"] == alert2["id"]
    assert alert2["repeat_count"] == 2

    # Verify that if status is changed to RESOLVED, a new event does NOT deduplicate
    client.patch(
        f"/api/v1/alerts/{alert1['id']}/status",
        json={"status": "ACKNOWLEDGED"},
        headers=auth_headers["analyst"]
    )
    client.patch(
        f"/api/v1/alerts/{alert1['id']}/status",
        json={"status": "INVESTIGATING"},
        headers=auth_headers["analyst"]
    )
    client.patch(
        f"/api/v1/alerts/{alert1['id']}/status",
        json={"status": "RESOLVED"},
        headers=auth_headers["analyst"]
    )

    payload3 = {
        "event_id": "evt-dedup-3",
        "assessment": get_mock_assessment(),
        "source_ip": "192.168.1.104",
        "destination_ip": "10.0.0.5",
        "protocol": "TCP"
    }
    res3 = client.post("/api/v1/alerts/evaluate", json=payload3, headers=auth_headers["analyst"])
    assert res3.status_code == 201
    alert3 = res3.json()

    assert alert3["id"] != alert1["id"]  # Created new alert since previous was RESOLVED (inactive)
    assert alert3["repeat_count"] == 1

def test_incident_correlation(client, auth_headers):
    # 1. Create an incident manually
    inc_res = client.post(
        "/api/v1/incidents/",
        json={"title": "Test Incident", "description": "Analyzing DDOS vectors.", "priority": "P3"},
        headers=auth_headers["analyst"]
    )
    assert inc_res.status_code == 201
    incident = inc_res.json()

    # 2. Trigger first alert (will create unassociated alert since no existing alert is linked to incident yet to provide source_ip mapping)
    payload1 = {
        "event_id": "evt-corr-1",
        "assessment": get_mock_assessment(dataset="cicids2017", predicted_class="DDoS"),
        "source_ip": "192.168.200.5",
        "destination_ip": "10.0.0.10",
        "protocol": "TCP"
    }
    res1 = client.post("/api/v1/alerts/evaluate", json=payload1, headers=auth_headers["analyst"])
    assert res1.status_code == 201
    alert1 = res1.json()
    assert alert1["incident_id"] is None

    # Link alert1 manually to incident
    link_res = client.post(
        f"/api/v1/incidents/{incident['id']}/alerts",
        json={"alert_id": alert1["id"]},
        headers=auth_headers["analyst"]
    )
    assert link_res.status_code == 200

    # 3. Trigger second alert with same dataset, source_ip, and attack_type
    # It should automatically correlate to the incident via strong correlation
    payload2 = {
        "event_id": "evt-corr-2",
        "assessment": get_mock_assessment(dataset="cicids2017", predicted_class="DDoS", priority="P1"), # Upgraded to P1
        "source_ip": "192.168.200.5",
        "destination_ip": "10.0.0.11",
        "protocol": "TCP"
    }
    res2 = client.post("/api/v1/alerts/evaluate", json=payload2, headers=auth_headers["analyst"])
    assert res2.status_code == 201
    alert2 = res2.json()

    assert alert2["incident_id"] == incident["id"]
    assert alert2["correlation_type"] == "SAME_SOURCE_ATTACK"

    # Verify priority escalation on the incident (was P3, should now be P1 since P1 alert was correlated)
    inc_details = client.get(f"/api/v1/incidents/{incident['id']}", headers=auth_headers["analyst"]).json()
    assert inc_details["priority"] == "P1"

def test_alert_lifecycle_transitions(client, auth_headers):
    # Create Alert
    payload = {
        "event_id": "evt-lifecycle-1",
        "assessment": get_mock_assessment(),
        "source_ip": "192.168.1.105"
    }
    alert = client.post("/api/v1/alerts/evaluate", json=payload, headers=auth_headers["analyst"]).json()

    # 1. NEW -> ACKNOWLEDGED
    res = client.patch(
        f"/api/v1/alerts/{alert['id']}/status",
        json={"status": "ACKNOWLEDGED", "reason": "Acknowledged by SOC analyst."},
        headers=auth_headers["analyst"]
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ACKNOWLEDGED"

    # 2. Reject invalid transitions (e.g. CLOSED requires Admin role, Analyst should be forbidden)
    res = client.patch(
        f"/api/v1/alerts/{alert['id']}/status",
        json={"status": "CLOSED"},
        headers=auth_headers["analyst"]
    )
    assert res.status_code == 403

    # 3. Admin can transition to CLOSED
    res = client.patch(
        f"/api/v1/alerts/{alert['id']}/status",
        json={"status": "CLOSED"},
        headers=auth_headers["admin"]
    )
    assert res.status_code == 200
    assert res.json()["status"] == "CLOSED"

    # 4. Reject impossible transitions (e.g. NEW -> RESOLVED directly without acknowledgment/investigation)
    alert2 = client.post(
        "/api/v1/alerts/evaluate",
        json={"event_id": "evt-lifecycle-2", "assessment": get_mock_assessment()},
        headers=auth_headers["analyst"]
    ).json()

    res = client.patch(
        f"/api/v1/alerts/{alert2['id']}/status",
        json={"status": "RESOLVED"},
        headers=auth_headers["analyst"]
    )
    assert res.status_code == 400

def test_incident_lifecycle_transitions(client, auth_headers):
    # Create incident
    incident = client.post(
        "/api/v1/incidents/",
        json={"title": "DDoS Incident", "description": "DDoS triage"},
        headers=auth_headers["analyst"]
    ).json()

    # OPEN -> INVESTIGATING
    res = client.patch(
        f"/api/v1/incidents/{incident['id']}/status",
        json={"status": "INVESTIGATING"},
        headers=auth_headers["analyst"]
    )
    assert res.status_code == 200
    assert res.json()["status"] == "INVESTIGATING"

    # Only admin can close
    res = client.patch(
        f"/api/v1/incidents/{incident['id']}/status",
        json={"status": "CLOSED"},
        headers=auth_headers["analyst"]
    )
    assert res.status_code == 403

    res = client.patch(
        f"/api/v1/incidents/{incident['id']}/status",
        json={"status": "CLOSED"},
        headers=auth_headers["admin"]
    )
    assert res.status_code == 200
    assert res.json()["status"] == "CLOSED"

def test_rbac_restrictions(client, auth_headers):
    # 1. Non-logged-in requests should return 401
    res = client.get("/api/v1/alerts/")
    assert res.status_code == 401

    # 2. Assignment endpoints require Admin
    res = client.patch(
        "/api/v1/alerts/9999/assign",
        json={"assigned_to": 1},
        headers=auth_headers["analyst"]
    )
    assert res.status_code == 403

def test_audit_history(client, auth_headers):
    # Create Alert
    alert = client.post(
        "/api/v1/alerts/evaluate",
        json={"event_id": "evt-audit-1", "assessment": get_mock_assessment()},
        headers=auth_headers["analyst"]
    ).json()

    # Update status
    client.patch(
        f"/api/v1/alerts/{alert['id']}/status",
        json={"status": "ACKNOWLEDGED", "reason": "Triage start"},
        headers=auth_headers["analyst"]
    )

    # Fetch History
    history_res = client.get(f"/api/v1/alerts/{alert['id']}/history", headers=auth_headers["analyst"])
    assert history_res.status_code == 200
    history = history_res.json()
    
    actions = [h["action"] for h in history]
    assert "CREATED" in actions
    assert "STATUS_CHANGED" in actions
    assert history[0]["action_metadata"] is not None

def test_filtering_and_pagination(client, auth_headers):
    # Ingest 3 distinct alerts
    for i in range(3):
        client.post(
            "/api/v1/alerts/evaluate",
            json={
                "event_id": f"evt-filter-{i}",
                "assessment": get_mock_assessment(dataset="unsw_nb15" if i == 0 else "cicids2017"),
                "source_ip": "10.0.0.50",
                "destination_ip": "10.0.0.1"
            },
            headers=auth_headers["analyst"]
        )

    # 1. Verify Dataset filter
    res = client.get("/api/v1/alerts/?dataset=unsw_nb15", headers=auth_headers["analyst"])
    assert len(res.json()) == 1

    # 2. Verify Pagination limit
    res_paginated = client.get("/api/v1/alerts/?limit=2", headers=auth_headers["analyst"])
    assert len(res_paginated.json()) == 2
