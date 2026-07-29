from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, and_
from app.models.alert import Alert
from app.models.alert_history import AlertHistory
from app.config.settings import settings
from ml.threat_detection.schemas import UnifiedThreatAssessment
from app.services.alert_policy_service import AlertPolicyService
from app.services.alert_deduplication_service import AlertDeduplicationService
from app.services.alert_correlation_service import AlertCorrelationService
from app.services.incident_service import IncidentService
from app.services.notification_service import NotificationService
from app.schemas.notification import NotificationPayload

class AlertService:
    """
    Orchestrates the Alert lifecycle: evaluation of assessments, idempotency checks,
    deduplication, correlation, status transitions, and assignment.
    """
    @staticmethod
    def evaluate_threat_assessment(
        db: Session,
        event_id: str,
        assessment: UnifiedThreatAssessment,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        destination_port: int | None = None,
        protocol: str | None = None,
        performed_by: int | None = None
    ) -> Alert | None:
        """
        Ingest, check idempotency, evaluate policy, deduplicate, correlate, and persist alerts.
        """
        # 1. Idempotency Check
        idempotency_stmt = select(Alert).where(Alert.event_id == event_id)
        existing_event = db.execute(idempotency_stmt).scalars().first()
        if existing_event:
            # Event has already been processed idempotently
            return existing_event

        # 2. Evaluate Alert Policy
        should_alert = AlertPolicyService.should_generate_alert(
            threat_score=assessment.risk.threat_score,
            risk_level=assessment.risk.risk_level,
            signal_status=assessment.signal_status
        )
        if not should_alert:
            return None

        # Determine Alert Type & Title
        sig_upper = assessment.signal_status.upper()
        if assessment.signal_status == "confirmed_attack":
            alert_type = "CONFIRMED_ATTACK"
            title = f"CRITICAL Attack Confirmed: {assessment.attack_classification.predicted_class or 'Unknown'}"
        elif assessment.signal_status == "intrusion_only":
            alert_type = "INTRUSION_DETECTED"
            title = f"High Security Intrusion Detected"
        else:
            alert_type = "ANOMALY_DETECTED"
            title = f"Anomalous Network Activity Detected"

        # 3. Deduplication Check
        dedup_key = AlertDeduplicationService.calculate_deduplication_key(
            dataset=assessment.dataset,
            signal_status=assessment.signal_status,
            attack_type=assessment.attack_classification.predicted_class,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            priority=assessment.risk.priority
        )

        matching_alert = AlertDeduplicationService.find_matching_active_alert(db, dedup_key)
        if matching_alert:
            # Merge/Deduplicate
            matching_alert.repeat_count += 1
            matching_alert.updated_at = datetime.now()
            # Keep highest threat score
            matching_alert.threat_score = max(matching_alert.threat_score, assessment.risk.threat_score)
            db.commit()
            db.refresh(matching_alert)

            # Log deduplication history
            history = AlertHistory(
                alert_id=matching_alert.id,
                action="DEDUPLICATED",
                performed_by=performed_by,
                action_metadata={"event_id": event_id, "threat_score": assessment.risk.threat_score}
            )
            db.add(history)
            db.commit()

            return matching_alert

        # 4. Create New Alert
        new_alert = Alert(
            event_id=event_id,
            deduplication_key=dedup_key,
            dataset=assessment.dataset.lower(),
            status="NEW",
            severity=assessment.risk.severity,
            priority=assessment.risk.priority,
            signal_status=assessment.signal_status,
            threat_score=assessment.risk.threat_score,
            risk_level=assessment.risk.risk_level,
            anomaly_detected=assessment.detection.anomaly_detected,
            anomaly_score=assessment.detection.anomaly_score,
            is_attack=assessment.intrusion_prediction.is_attack,
            attack_probability=assessment.intrusion_prediction.attack_probability,
            attack_type=assessment.attack_classification.predicted_class,
            classification_confidence=assessment.attack_classification.confidence,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            title=title,
            description=f"Threat score {assessment.risk.threat_score:.2f} (Risk: {assessment.risk.risk_level}). Anomaly: {assessment.detection.anomaly_detected}, Attack: {assessment.intrusion_prediction.is_attack} ({assessment.attack_classification.predicted_class or 'N/A'}).",
            reasons=assessment.reasons,
            repeat_count=1,
            source="NETSHIELD_AI",
            alert_type=alert_type,
            pipeline_version="1.0"
        )

        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        # 5. Incident Correlation
        corr_type, corr_reason, corr_incident_id = AlertCorrelationService.correlate_alert_to_incident(
            db=db,
            dataset=assessment.dataset.lower(),
            source_ip=source_ip,
            attack_type=assessment.attack_classification.predicted_class
        )

        if corr_incident_id:
            new_alert.correlation_type = corr_type
            new_alert.correlation_reason = corr_reason
            db.commit()
            
            # Link via IncidentService to manage escalations
            IncidentService.associate_alert_to_incident(
                db=db,
                incident_id=corr_incident_id,
                alert_id=new_alert.id,
                performed_by=performed_by
            )
        elif settings.ALERT_AUTO_CREATE_INCIDENTS and assessment.risk.priority in ["P1", "P2"]:
            # Auto-create incident for P1/P2 alerts
            incident_title = f"Auto-Incident: {title}"
            new_incident = IncidentService.create_incident(
                db=db,
                title=incident_title,
                description=f"Auto-generated incident for high priority alert: {new_alert.title}",
                priority=assessment.risk.priority,
                performed_by=performed_by
            )
            new_alert.correlation_type = "SAME_SOURCE"  # auto correlation
            new_alert.correlation_reason = f"Auto-created incident #{new_incident.id} for priority {assessment.risk.priority} alert."
            db.commit()
            
            # Associate to trigger escalation / audit
            IncidentService.associate_alert_to_incident(
                db=db,
                incident_id=new_incident.id,
                alert_id=new_alert.id,
                performed_by=performed_by
            )
        else:
            # Leave unassociated
            new_alert.correlation_type = "NONE"
            new_alert.correlation_reason = "No active incident matched correlation criteria"
            db.commit()

        # 6. Log Alert History
        history = AlertHistory(
            alert_id=new_alert.id,
            action="CREATED",
            new_status="NEW",
            performed_by=performed_by,
            action_metadata={"event_id": event_id}
        )
        db.add(history)
        db.commit()

        # 7. Dispatch Notification ready event
        notif_payload = NotificationPayload(
            event_type="ALERT_CREATED",
            alert_id=new_alert.id,
            incident_id=new_alert.incident_id,
            timestamp=datetime.now(),
            title=new_alert.title,
            severity=new_alert.severity,
            priority=new_alert.priority,
            risk_level=new_alert.risk_level,
            threat_score=new_alert.threat_score,
            signal_status=new_alert.signal_status,
            attack_type=new_alert.attack_type,
            source_ip=new_alert.source_ip,
            destination_ip=new_alert.destination_ip,
            source_port=new_alert.source_port,
            destination_port=new_alert.destination_port,
            protocol=new_alert.protocol,
            summary=new_alert.description,
            reasons=new_alert.reasons or []
        )
        NotificationService.dispatch_notification(notif_payload)

        return new_alert

    @staticmethod
    def update_alert_status(
        db: Session,
        alert_id: int,
        new_status: str,
        performed_by: int | None = None,
        reason: str | None = None
    ) -> Alert:
        """
        Updates status on an alert, validating transitions and logging history.
        """
        alert = db.get(Alert, alert_id)
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found")

        old_status = alert.status
        if old_status == new_status:
            return alert

        # Validate transitions
        # Allowed:
        # NEW -> ACKNOWLEDGED, NEW -> INVESTIGATING, NEW -> FALSE_POSITIVE, NEW -> CLOSED
        # ACKNOWLEDGED -> INVESTIGATING, ACKNOWLEDGED -> FALSE_POSITIVE, ACKNOWLEDGED -> RESOLVED, ACKNOWLEDGED -> CLOSED
        # INVESTIGATING -> RESOLVED, INVESTIGATING -> FALSE_POSITIVE, INVESTIGATING -> CLOSED
        # RESOLVED -> CLOSED, RESOLVED -> INVESTIGATING (reopen)
        # FALSE_POSITIVE -> CLOSED, FALSE_POSITIVE -> INVESTIGATING (reopen)
        # CLOSED -> INVESTIGATING (reopen)
        valid = False
        o, n = old_status.upper(), new_status.upper()
        if o == "NEW" and n in ["ACKNOWLEDGED", "INVESTIGATING", "FALSE_POSITIVE", "CLOSED"]:
            valid = True
        elif o == "ACKNOWLEDGED" and n in ["INVESTIGATING", "FALSE_POSITIVE", "RESOLVED", "CLOSED"]:
            valid = True
        elif o == "INVESTIGATING" and n in ["RESOLVED", "FALSE_POSITIVE", "CLOSED"]:
            valid = True
        elif o == "RESOLVED" and n in ["CLOSED", "INVESTIGATING"]:
            valid = True
        elif o == "FALSE_POSITIVE" and n in ["CLOSED", "INVESTIGATING"]:
            valid = True
        elif o == "CLOSED" and n in ["INVESTIGATING"]:
            valid = True

        if not valid:
            raise ValueError(f"Invalid alert status transition from {old_status} to {new_status}")

        # Update status
        alert.status = n

        if n == "ACKNOWLEDGED":
            alert.acknowledged_by = performed_by
            alert.acknowledged_at = datetime.now()
        elif n == "RESOLVED":
            alert.resolved_by = performed_by
            alert.resolved_at = datetime.now()
            
        db.commit()
        db.refresh(alert)

        # Log history
        meta = {}
        if reason:
            meta["reason"] = reason

        history = AlertHistory(
            alert_id=alert.id,
            action="STATUS_CHANGED",
            old_status=old_status,
            new_status=n,
            performed_by=performed_by,
            action_metadata=meta
        )
        db.add(history)
        db.commit()

        # Dispatch notification
        notif_payload = NotificationPayload(
            event_type="ALERT_STATUS_UPDATED",
            alert_id=alert.id,
            incident_id=alert.incident_id,
            timestamp=datetime.now(),
            title=f"Alert Status Updated: {alert.title}",
            severity=alert.severity,
            priority=alert.priority,
            risk_level=alert.risk_level,
            threat_score=alert.threat_score,
            signal_status=alert.signal_status,
            attack_type=alert.attack_type,
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            source_port=alert.source_port,
            destination_port=alert.destination_port,
            protocol=alert.protocol,
            summary=f"Alert status transitioned from {old_status} to {n}. Reason: {reason or 'None'}",
            reasons=alert.reasons or []
        )
        NotificationService.dispatch_notification(notif_payload)

        return alert

    @staticmethod
    def assign_alert(
        db: Session,
        alert_id: int,
        assigned_to: int | None,
        performed_by: int | None = None
    ) -> Alert:
        """
        Assigns or unassigns an alert to an analyst.
        """
        alert = db.get(Alert, alert_id)
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found")

        old_assigned = alert.assigned_to
        alert.assigned_to = assigned_to
        db.commit()
        db.refresh(alert)

        # Log History
        history = AlertHistory(
            alert_id=alert.id,
            action="ASSIGNED",
            performed_by=performed_by,
            action_metadata={"old_assignee": old_assigned, "new_assignee": assigned_to}
        )
        db.add(history)
        db.commit()

        return alert
