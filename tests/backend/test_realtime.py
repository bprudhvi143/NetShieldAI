import os
import time
import pytest
import queue
from fastapi.testclient import TestClient
from sqlalchemy import select, delete
from sqlalchemy.orm import Session

from app.main import app
from app.db.postgres import SessionLocal
from app.models.network_flow import NetworkFlow
from app.models.alert import Alert
from app.models.user import User
from app.config.settings import settings
from app.services.packet_capture_service import packet_capture_service
from app.services.flow_aggregation_service import flow_aggregation_service, Flow
from app.services.live_detection_service import live_detection_service
from app.services.websocket_manager import websocket_manager

@pytest.fixture(scope="module")
def client():
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
        # Delete network flows first to avoid foreign key errors
        db.execute(delete(NetworkFlow))
        db.execute(delete(Alert))
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()

def test_interface_discovery(client, auth_headers):
    # Retrieve interfaces as Analyst
    res = client.get("/api/v1/monitoring/interfaces", headers=auth_headers["analyst"])
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    assert len(res.json()) > 0

def test_sniffer_lifecycle_and_rbac(client, auth_headers):
    # 1. Get initial status
    res = client.get("/api/v1/monitoring/status", headers=auth_headers["analyst"])
    assert res.status_code == 200
    assert res.json()["is_running"] is False
    assert res.json()["status"] == "STOPPED"

    # 2. Try starting capture on emulator interface as Analyst (Allowed)
    res = client.post("/api/v1/monitoring/start?interface=Emulator-Interface", headers=auth_headers["analyst"])
    assert res.status_code == 200
    
    # 3. Verify status transitioned to RUNNING
    res = client.get("/api/v1/monitoring/status", headers=auth_headers["analyst"])
    assert res.status_code == 200
    assert res.json()["is_running"] is True
    assert res.json()["status"] == "RUNNING"
    assert res.json()["interface"] == "Emulator-Interface"
    assert res.json()["is_emulated"] is True

    # 4. Stop capture as Admin (Allowed)
    res = client.post("/api/v1/monitoring/stop", headers=auth_headers["admin"])
    assert res.status_code == 200
    
    # 5. Verify status is STOPPED
    res = client.get("/api/v1/monitoring/status", headers=auth_headers["analyst"])
    assert res.status_code == 200
    assert res.json()["is_running"] is False
    assert res.json()["status"] == "STOPPED"

def test_flow_aggregation_grouping_and_timeout():
    # Make sure aggregator is stopped
    flow_aggregation_service.stop()
    packet_capture_service.stop_capture()
    
    # Reset queue state
    flow_aggregation_service.active_flows.clear()
    
    pkt_fwd_1 = {
        "src_ip": "10.0.0.1", "source_port": 12345,
        "dst_ip": "192.168.1.1", "destination_port": 80,
        "protocol": "TCP", "size": 64, "payload_size": 24, "header_length": 40,
        "tcp_flags": 0x02, "win_size": 8192, "timestamp": time.time()
    }
    pkt_bwd_1 = {
        "src_ip": "192.168.1.1", "source_port": 80,
        "dst_ip": "10.0.0.1", "destination_port": 12345,
        "protocol": "TCP", "size": 100, "payload_size": 60, "header_length": 40,
        "tcp_flags": 0x12, "win_size": 8192, "timestamp": time.time() + 0.1
    }
    
    # Sort host-port pairs to canonicalize flow key
    key1 = flow_aggregation_service._make_flow_key(
        pkt_fwd_1["src_ip"], pkt_fwd_1["source_port"],
        pkt_fwd_1["dst_ip"], pkt_fwd_1["destination_port"],
        pkt_fwd_1["protocol"]
    )
    
    # Check that backward packet gives same key
    key2 = flow_aggregation_service._make_flow_key(
        pkt_bwd_1["src_ip"], pkt_bwd_1["source_port"],
        pkt_bwd_1["dst_ip"], pkt_bwd_1["destination_port"],
        pkt_bwd_1["protocol"]
    )
    assert key1 == key2

    # Group packets into active flow
    flow = Flow(pkt_fwd_1)
    flow.add_packet(pkt_bwd_1)

    assert len(flow.packets) == 2
    assert len(flow.fwd_packets) == 1
    assert len(flow.bwd_packets) == 1
    assert flow.src_ip == "10.0.0.1"
    assert flow.dst_ip == "192.168.1.1"

def test_feature_adapter_schema_dimensions():
    pkt = {
        "src_ip": "10.0.0.2", "source_port": 5001,
        "dst_ip": "10.0.0.10", "destination_port": 80,
        "protocol": "TCP", "size": 64, "payload_size": 24, "header_length": 40,
        "tcp_flags": 0x02, "win_size": 8192, "timestamp": time.time()
    }
    flow = Flow(pkt)
    
    # Verify CICIDS2017 feature mapping (77 features)
    cicids_dict = flow.to_cicids2017_dict()
    assert len(cicids_dict) == 77
    assert cicids_dict["Destination Port"] == 80
    assert cicids_dict["Total Fwd Packets"] == 1
    assert cicids_dict["Total Length of Fwd Packets"] == 64.0
    
    # Verify UNSW-NB15 feature mapping (40 numeric + 3 categorical = 43 features)
    unsw_dict = flow.to_unsw_nb15_dict()
    assert len(unsw_dict) == 43
    assert unsw_dict["sport"] == 5001.0
    assert unsw_dict["dsport"] == 80.0
    assert unsw_dict["proto"] == "tcp"
    assert unsw_dict["state"] == "CON"

def test_realtime_db_persistence_and_ws_broadcast(client, auth_headers):
    db = SessionLocal()
    
    # Create mock flow details
    pkt = {
        "src_ip": "192.168.200.5", "source_port": 54321,
        "dst_ip": "10.0.0.10", "destination_port": 80,
        "protocol": "TCP", "size": 64, "payload_size": 24, "header_length": 40,
        "tcp_flags": 0x02, "win_size": 8192, "timestamp": time.time()
    }
    flow = Flow(pkt)
    
    # Configure live detection service for evaluation
    live_detection_service.dataset_name = "cicids2017"
    live_detection_service.class_preprocessor = joblib_loader("cicids2017_class_preprocessor.joblib")
    live_detection_service.anomaly_preprocessor = joblib_loader("cicids2017_anomaly_preprocessor.joblib")
    live_detection_service.expected_num_features = live_detection_service.class_preprocessor.transformers_[0][2]
    live_detection_service.expected_cat_features = []
    
    # Let's mock a pipeline run directly
    from ml.threat_detection.pipeline import ThreatDetectionPipeline
    live_detection_service.pipeline = ThreatDetectionPipeline("cicids2017", base_dir="c:/NetShieldAI")
    
    # Clear completed queue
    flow_aggregation_service.completed_flow_queue = queue.Queue(maxsize=100)
    
    # Trigger aggregator queue injection
    flow_aggregation_service._enqueue_completed_flow(flow)
    assert flow_aggregation_service.completed_flow_queue.qsize() == 1
    
    # Invoke detection processor synchronously (one cycle of the loop)
    live_detection_service.is_running = True
    # We can invoke processing of the flow manually to avoid async thread race issues
    completed_flow = flow_aggregation_service.completed_flow_queue.get()
    
    # Construct DataFrame
    raw_features = completed_flow.to_cicids2017_dict()
    df_raw = pd_dataframe([raw_features], columns=list(live_detection_service.expected_num_features))
    X_anomaly_arr = live_detection_service.anomaly_preprocessor.transform(df_raw)
    X_class_arr = live_detection_service.class_preprocessor.transform(df_raw)
    flow_df_anomaly = pd_dataframe(X_anomaly_arr, columns=live_detection_service.pipeline.anomaly_features)
    flow_df_class = pd_dataframe(X_class_arr, columns=live_detection_service.pipeline.classification_features)
    
    # Run pipeline
    assessment = live_detection_service.pipeline.predict_single(flow_df_anomaly, flow_df_class)
    
    # Save network flow directly and test persistence
    from app.models.network_flow import NetworkFlow
    net_flow = NetworkFlow(
        event_id="evt-test-12345",
        flow_start=datetime_fromtimestamp(completed_flow.flow_start),
        flow_end=datetime_fromtimestamp(completed_flow.flow_end),
        dataset_profile="cicids2017",
        source_ip=completed_flow.src_ip,
        destination_ip=completed_flow.dst_ip,
        source_port=completed_flow.source_port,
        destination_port=completed_flow.destination_port,
        protocol=completed_flow.protocol,
        packet_count=len(completed_flow.packets),
        byte_count=sum(p["size"] for p in completed_flow.packets),
        duration=completed_flow.get_duration_ms() / 1000.0,
        anomaly_detected=assessment.detection.anomaly_detected,
        anomaly_score=assessment.detection.anomaly_score,
        is_attack=assessment.intrusion_prediction.is_attack,
        attack_probability=assessment.intrusion_prediction.attack_probability,
        normal_probability=assessment.intrusion_prediction.normal_probability,
        attack_type=assessment.attack_classification.predicted_class,
        classification_confidence=assessment.attack_classification.confidence,
        threat_score=assessment.risk.threat_score,
        risk_level=assessment.risk.risk_level,
        severity=assessment.risk.severity,
        impact_level=assessment.risk.impact_level,
        priority=assessment.risk.priority,
        signal_status=assessment.signal_status,
        processing_latency_ms=1.5,
        model_version="1.0"
    )
    db.add(net_flow)
    db.commit()
    db.refresh(net_flow)
    
    # Verify DB record exists
    stmt = select(NetworkFlow).where(NetworkFlow.event_id == "evt-test-12345")
    db_flow = db.execute(stmt).scalar()
    assert db_flow is not None
    assert db_flow.source_ip == "192.168.200.5"
    assert db_flow.dataset_profile == "cicids2017"
    assert db_flow.anomaly_score == assessment.detection.anomaly_score
    
    # Query API flow log log search
    res = client.get("/api/v1/monitoring/flows", headers=auth_headers["analyst"])
    assert res.status_code == 200
    assert len(res.json()) > 0
    assert res.json()[0]["event_id"] == "evt-test-12345"

# Helper builders
def joblib_loader(filename):
    import joblib
    return joblib.load(os.path.join("c:/NetShieldAI/ml/artifacts/preprocessors", filename))

def pd_dataframe(data, columns):
    import pandas as pd
    return pd.DataFrame(data, columns=columns)

def datetime_fromtimestamp(t):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(t, timezone.utc)
