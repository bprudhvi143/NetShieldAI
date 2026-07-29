import os
import time
import queue
import threading
import joblib
import pandas as pd
from datetime import datetime, timezone
import logging
from typing import Dict, Any, Optional

from app.config.settings import settings
from app.db.postgres import SessionLocal
from app.models.network_flow import NetworkFlow
from app.services.alert_service import AlertService
from app.services.alert_policy_service import AlertPolicyService
from app.services.websocket_manager import websocket_manager
from ml.threat_detection.pipeline import ThreatDetectionPipeline

logger = logging.getLogger("app.live_detection")

class LiveDetectionService:
    """
    Background worker service that consumes completed flows, maps raw metrics,
    applies model-specific scaling, triggers the Phase 5 ML pipeline,
    records results to PostgreSQL, and broadcasts real-time updates.
    """
    def __init__(self, base_dir: str = "c:/NetShieldAI"):
        self.base_dir = base_dir
        self.thread = None
        self.is_running = False
        
        self.pipeline: Optional[ThreatDetectionPipeline] = None
        self.class_preprocessor = None
        self.anomaly_preprocessor = None
        self.dataset_name = None
        self.pipeline_version = "1.0"
        
        # Diagnostics
        self.threats_detected = 0
        self.last_latency_ms = 0.0
        self.sum_latency_ms = 0.0
        self.processed_count = 0

    def start(self):
        if self.is_running:
            return
        
        # Initialize ML pipeline and load preprocessors based on active profile
        self.dataset_name = settings.LIVE_MODEL_PROFILE.lower().replace("-", "_")
        logger.info(f"Initializing LiveDetectionService with profile: {self.dataset_name.upper()}")
        
        try:
            self.pipeline = ThreatDetectionPipeline(self.dataset_name, self.base_dir)
            self.pipeline_version = self.pipeline.pipeline_version
            
            # Load preprocessor artifacts
            preprocessor_path = os.path.join(self.base_dir, "ml/artifacts/preprocessors")
            self.class_preprocessor = joblib.load(
                os.path.join(preprocessor_path, f"{self.dataset_name}_class_preprocessor.joblib")
            )
            self.anomaly_preprocessor = joblib.load(
                os.path.join(preprocessor_path, f"{self.dataset_name}_anomaly_preprocessor.joblib")
            )
            logger.info("ML preprocessors successfully loaded.")
        except Exception as e:
            logger.critical(f"Failed to initialize live detection pipeline: {e}")
            raise e

        # Resolve numerical and categorical features expected as input
        self.expected_num_features = self.class_preprocessor.transformers_[0][2]
        self.expected_cat_features = []
        if len(self.class_preprocessor.transformers_) > 1:
            self.expected_cat_features = self.class_preprocessor.transformers_[1][2]
            
        self.is_running = True
        self.processed_count = 0
        self.sum_latency_ms = 0.0
        self.threats_detected = 0
        
        from app.services.flow_aggregation_service import flow_aggregation_service
        self.thread = threading.Thread(
            target=self._run_detector, 
            args=(flow_aggregation_service.completed_flow_queue,), 
            name="LiveDetectionThread", 
            daemon=True
        )
        self.thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3.0)
            self.thread = None
        logger.info("Live detection service stopped.")

    def _run_detector(self, completed_queue: queue.Queue):
        logger.info("Live detection worker thread active.")
        
        while self.is_running:
            try:
                # Read flow from queue (with a short timeout to check loop flag)
                flow = completed_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            start_time = time.perf_counter()
            event_id = f"evt-{self.dataset_name}-{int(time.time()*1000)}-{random_str(4)}"
            
            try:
                # 1. Extract raw features dictionary
                if self.dataset_name == "cicids2017":
                    raw_features = flow.to_cicids2017_dict()
                else:
                    raw_features = flow.to_unsw_nb15_dict()

                # 2. Format to DataFrame & order features
                df_raw = pd.DataFrame([raw_features])
                
                # Align categorical columns filling NaNs
                for c in self.expected_cat_features:
                    if c not in df_raw.columns or pd.isna(df_raw[c].iloc[0]):
                        df_raw[c] = "Unknown"
                    else:
                        df_raw[c] = str(df_raw[c].iloc[0])

                # Align numerical columns
                for c in self.expected_num_features:
                    if c not in df_raw.columns or pd.isna(df_raw[c].iloc[0]):
                        df_raw[c] = 0.0

                # Ensure exact column ordering matching fit phase
                ordered_cols = list(self.expected_num_features) + list(self.expected_cat_features)
                df_raw = df_raw[ordered_cols]

                # 3. Apply transformer scaling/one-hot encoding
                X_anomaly_arr = self.anomaly_preprocessor.transform(df_raw)
                X_class_arr = self.class_preprocessor.transform(df_raw)

                # Reconstruct pandas DataFrame with standard feature names expected by pipeline
                flow_df_anomaly = pd.DataFrame(X_anomaly_arr, columns=self.pipeline.anomaly_features)
                flow_df_class = pd.DataFrame(X_class_arr, columns=self.pipeline.classification_features)

                # 4. Execute Phase 5 Orchestrated Predict
                assessment = self.pipeline.predict_single(flow_df_anomaly, flow_df_class)

                latency_ms = (time.perf_counter() - start_time) * 1000.0
                self.last_latency_ms = latency_ms
                self.processed_count += 1
                self.sum_latency_ms += latency_ms

                # 5. Database transactional persistence
                db = SessionLocal()
                try:
                    alert_obj = None
                    # Evaluate if threat qualifies for Alerting
                    if AlertPolicyService.evaluate_policy(assessment):
                        self.threats_detected += 1
                        alert_obj = AlertService.create_alert(
                            db=db,
                            event_id=event_id,
                            assessment=assessment,
                            source_ip=flow.src_ip,
                            destination_ip=flow.dst_ip,
                            source_port=flow.source_port,
                            destination_port=flow.destination_port,
                            protocol=flow.protocol,
                            performed_by=None
                        )

                    # Persist network flow record
                    net_flow = NetworkFlow(
                        event_id=event_id,
                        flow_start=datetime.fromtimestamp(flow.flow_start, timezone.utc),
                        flow_end=datetime.fromtimestamp(flow.flow_end, timezone.utc),
                        dataset_profile=self.dataset_name,
                        source_ip=flow.src_ip,
                        destination_ip=flow.dst_ip,
                        source_port=flow.source_port,
                        destination_port=flow.destination_port,
                        protocol=flow.protocol,
                        packet_count=len(flow.packets),
                        byte_count=sum(p["size"] for p in flow.packets),
                        duration=flow.get_duration_ms() / 1000.0,
                        feature_snapshot=raw_features,
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
                        alert_id=alert_obj.id if alert_obj else None,
                        incident_id=alert_obj.incident_id if (alert_obj and alert_obj.incident_id) else None,
                        processing_latency_ms=latency_ms,
                        model_version=self.pipeline_version
                    )
                    db.add(net_flow)
                    db.commit()
                    db.refresh(net_flow)

                    # 6. Broadcast payload through WebSocket Event Bus
                    self._broadcast_events(net_flow, alert_obj)

                except Exception as db_err:
                    db.rollback()
                    logger.error(f"Failed to persist live detection results: {db_err}")
                finally:
                    db.close()

            except Exception as ml_err:
                logger.error(f"Inference pipeline failed on completed flow: {ml_err}")

def random_str(length=4) -> str:
    import string
    import random
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choice(chars) for _ in range(length))

# Global live detection service instance
live_detection_service = LiveDetectionService()

def _broadcast_events(net_flow: NetworkFlow, alert_obj: Optional[Any]):
    # Broadcast processed flow
    flow_payload = {
        "id": net_flow.id,
        "event_id": net_flow.event_id,
        "captured_at": net_flow.captured_at.isoformat(),
        "flow_start": net_flow.flow_start.isoformat(),
        "flow_end": net_flow.flow_end.isoformat(),
        "dataset_profile": net_flow.dataset_profile,
        "source_ip": net_flow.source_ip,
        "destination_ip": net_flow.destination_ip,
        "source_port": net_flow.source_port,
        "destination_port": net_flow.destination_port,
        "protocol": net_flow.protocol,
        "packet_count": net_flow.packet_count,
        "byte_count": net_flow.byte_count,
        "duration": net_flow.duration,
        "anomaly_detected": net_flow.anomaly_detected,
        "anomaly_score": net_flow.anomaly_score,
        "is_attack": net_flow.is_attack,
        "attack_probability": net_flow.attack_probability,
        "attack_type": net_flow.attack_type,
        "threat_score": net_flow.threat_score,
        "risk_level": net_flow.risk_level,
        "priority": net_flow.priority,
        "signal_status": net_flow.signal_status,
        "alert_id": net_flow.alert_id,
        "incident_id": net_flow.incident_id
    }
    
    websocket_manager.broadcast({
        "event_type": "flow.processed",
        "event_id": net_flow.event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": flow_payload
    })
    
    # Broadcast alert details if generated
    if alert_obj:
        websocket_manager.broadcast({
            "event_type": "alert.created" if alert_obj.repeat_count == 1 else "alert.updated",
            "event_id": alert_obj.event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {
                "id": alert_obj.id,
                "event_id": alert_obj.event_id,
                "status": alert_obj.status,
                "severity": alert_obj.severity,
                "priority": alert_obj.priority,
                "threat_score": alert_obj.threat_score,
                "risk_level": alert_obj.risk_level,
                "anomaly_detected": alert_obj.anomaly_detected,
                "is_attack": alert_obj.is_attack,
                "attack_type": alert_obj.attack_type,
                "source_ip": alert_obj.source_ip,
                "destination_ip": alert_obj.destination_ip,
                "source_port": alert_obj.source_port,
                "destination_port": alert_obj.destination_port,
                "protocol": alert_obj.protocol,
                "title": alert_obj.title,
                "description": alert_obj.description,
                "repeat_count": alert_obj.repeat_count,
                "incident_id": alert_obj.incident_id
            }
        })

# Assign helper method to class
LiveDetectionService._broadcast_events = _broadcast_events
