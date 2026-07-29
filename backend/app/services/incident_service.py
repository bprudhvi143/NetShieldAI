from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.incident import Incident
from app.models.incident_history import IncidentHistory
from app.models.alert import Alert
from app.models.alert_history import AlertHistory

PRIORITY_RANK = {
    "P1": 4,
    "P2": 3,
    "P3": 2,
    "P4": 1
}

class IncidentService:
    """
    Service responsible for incident lifecycle management, status changes,
    assignments, history, and priority escalation.
    """
    @staticmethod
    def create_incident(
        db: Session,
        title: str,
        description: str | None = None,
        priority: str = "P4",
        assigned_to: int | None = None,
        performed_by: int | None = None
    ) -> Incident:
        """
        Creates a new incident record and logs history.
        """
        incident = Incident(
            title=title,
            description=description,
            priority=priority,
            status="OPEN",
            assigned_to=assigned_to
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)

        # Log creation history
        history = IncidentHistory(
            incident_id=incident.id,
            action="CREATED",
            new_status="OPEN",
            performed_by=performed_by,
            action_metadata={"title": title, "priority": priority}
        )
        db.add(history)
        db.commit()
        
        return incident

    @staticmethod
    def update_incident_status(
        db: Session,
        incident_id: int,
        new_status: str,
        performed_by: int | None = None,
        reason: str | None = None
    ) -> Incident:
        """
        Updates an incident status, enforcing legal transitions and logging history.
        """
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found")

        old_status = incident.status
        if old_status == new_status:
            return incident

        # Validate transitions
        # OPEN -> INVESTIGATING, CLOSED
        # INVESTIGATING -> CONTAINED, RESOLVED, CLOSED
        # CONTAINED -> RESOLVED, CLOSED
        # RESOLVED -> CLOSED, INVESTIGATING (reopen)
        # CLOSED -> INVESTIGATING (reopen)
        valid = False
        o, n = old_status.upper(), new_status.upper()
        if o == "OPEN" and n in ["INVESTIGATING", "CLOSED"]:
            valid = True
        elif o == "INVESTIGATING" and n in ["CONTAINED", "RESOLVED", "CLOSED"]:
            valid = True
        elif o == "CONTAINED" and n in ["RESOLVED", "CLOSED"]:
            valid = True
        elif o == "RESOLVED" and n in ["CLOSED", "INVESTIGATING"]:
            valid = True
        elif o == "CLOSED" and n in ["INVESTIGATING"]:
            valid = True

        if not valid:
            raise ValueError(f"Invalid incident status transition from {old_status} to {new_status}")

        # Update status
        incident.status = n
        if n == "RESOLVED":
            incident.resolved_by = performed_by
            incident.resolved_at = datetime.now()
        else:
            incident.resolved_by = None
            incident.resolved_at = None
            
        db.commit()
        db.refresh(incident)

        # Log history
        meta = {}
        if reason:
            meta["reason"] = reason
            
        history = IncidentHistory(
            incident_id=incident.id,
            action="STATUS_CHANGED",
            old_status=old_status,
            new_status=n,
            performed_by=performed_by,
            action_metadata=meta
        )
        db.add(history)
        db.commit()

        return incident

    @staticmethod
    def assign_incident(
        db: Session,
        incident_id: int,
        assigned_to: int | None,
        performed_by: int | None = None
    ) -> Incident:
        """
        Assigns or unassigns an incident to an analyst, logging history.
        """
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found")

        old_assigned = incident.assigned_to
        incident.assigned_to = assigned_to
        db.commit()
        db.refresh(incident)

        history = IncidentHistory(
            incident_id=incident.id,
            action="ASSIGNED",
            performed_by=performed_by,
            action_metadata={"old_assigned": old_assigned, "new_assigned": assigned_to}
        )
        db.add(history)
        db.commit()

        return incident

    @staticmethod
    def associate_alert_to_incident(
        db: Session,
        incident_id: int,
        alert_id: int,
        performed_by: int | None = None
    ) -> Incident:
        """
        Links an alert to an incident, triggers priority escalation, and logs history.
        """
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found")

        alert = db.get(Alert, alert_id)
        if not alert:
            raise ValueError(f"Alert with ID {alert_id} not found")

        if alert.incident_id == incident_id:
            return incident

        old_incident_id = alert.incident_id
        alert.incident_id = incident_id
        db.commit()

        # Log Alert history change
        alert_history = AlertHistory(
            alert_id=alert.id,
            action="ASSOCIATED_WITH_INCIDENT",
            performed_by=performed_by,
            action_metadata={"old_incident_id": old_incident_id, "new_incident_id": incident_id}
        )
        db.add(alert_history)

        # Log Incident history change
        incident_history = IncidentHistory(
            incident_id=incident.id,
            action="ALERT_ATTACHED",
            performed_by=performed_by,
            action_metadata={"alert_id": alert_id}
        )
        db.add(incident_history)
        db.commit()

        # Escalation logic: Incident priority should be >= max of all associated active alerts
        IncidentService.escalate_incident_priority(db, incident_id)

        db.refresh(incident)
        return incident

    @staticmethod
    def escalate_incident_priority(
        db: Session,
        incident_id: int
    ) -> None:
        """
        Re-calculates the incident priority based on its associated alerts.
        It escalates the priority to the maximum priority rank of its alerts.
        Never automatically downgrades.
        """
        incident = db.get(Incident, incident_id)
        if not incident:
            return

        # Fetch all associated alerts
        stmt = select(Alert).where(Alert.incident_id == incident_id)
        alerts = db.execute(stmt).scalars().all()
        if not alerts:
            return

        max_rank = PRIORITY_RANK.get(incident.priority, 1)
        for a in alerts:
            a_rank = PRIORITY_RANK.get(a.priority, 1)
            if a_rank > max_rank:
                max_rank = a_rank

        # Convert rank back to priority string
        rank_to_p = {4: "P1", 3: "P2", 2: "P3", 1: "P4"}
        new_priority = rank_to_p.get(max_rank, "P4")

        if incident.priority != new_priority:
            incident.priority = new_priority
            db.commit()
