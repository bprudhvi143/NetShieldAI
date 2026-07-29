from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, desc

from app.db.postgres import get_db
from app.services.auth_service import RoleChecker
from app.models.user import User
from app.models.alert import Alert
from app.models.alert_history import AlertHistory
from app.schemas.alert import AlertRead, AlertStatusUpdate, AlertAssign, AlertHistoryRead
from app.services.alert_service import AlertService
from ml.threat_detection.schemas import UnifiedThreatAssessment
from pydantic import BaseModel, Field

router = APIRouter()

class AlertEvaluationRequest(BaseModel):
    event_id: str = Field(..., description="Unique event identifier for idempotency")
    assessment: UnifiedThreatAssessment = Field(..., description="Phase 5 unified threat assessment output")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    source_port: Optional[int] = Field(default=None, description="Source port")
    destination_port: Optional[int] = Field(default=None, description="Destination port")
    protocol: Optional[str] = Field(default=None, description="Protocol name")

@router.post("/evaluate", response_model=Optional[AlertRead], status_code=status.HTTP_201_CREATED)
def evaluate_threat_event(
    payload: AlertEvaluationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Ingest and evaluate a Phase 5 assessment. Returns the created/updated Alert,
    or null if the policy engine filtered it out.
    """
    try:
        alert = AlertService.evaluate_threat_assessment(
            db=db,
            event_id=payload.event_id,
            assessment=payload.assessment,
            source_ip=payload.source_ip,
            destination_ip=payload.destination_ip,
            source_port=payload.source_port,
            destination_port=payload.destination_port,
            protocol=payload.protocol,
            performed_by=current_user.id
        )
        return alert
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to evaluate threat event: {str(e)}"
        )

@router.get("/", response_model=List[AlertRead])
def list_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    priority: Optional[str] = None,
    signal_status: Optional[str] = None,
    attack_type: Optional[str] = None,
    dataset: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    assigned_to: Optional[int] = None,
    incident_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Query alerts with filtering and pagination.
    """
    stmt = select(Alert)
    conditions = []

    if status:
        conditions.append(Alert.status == status.upper())
    if severity:
        conditions.append(Alert.severity == severity)
    if priority:
        conditions.append(Alert.priority == priority.upper())
    if signal_status:
        conditions.append(Alert.signal_status == signal_status.lower())
    if attack_type:
        conditions.append(Alert.attack_type == attack_type)
    if dataset:
        conditions.append(Alert.dataset == dataset.lower())
    if start_time:
        conditions.append(Alert.created_at >= start_time)
    if end_time:
        conditions.append(Alert.created_at <= end_time)
    if assigned_to is not None:
        conditions.append(Alert.assigned_to == assigned_to)
    if incident_id is not None:
        conditions.append(Alert.incident_id == incident_id)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.order_by(desc(Alert.created_at)).offset(skip).limit(limit)
    return db.execute(stmt).scalars().all()

@router.get("/{alert_id}", response_model=AlertRead)
def get_alert_by_id(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Retrieve specific alert details.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )
    return alert

@router.patch("/{alert_id}/status", response_model=AlertRead)
def update_alert_status_endpoint(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Acknowledge, resolve, investigate, or close an alert.
    Note: Transitioning to CLOSED requires 'Security Admin' role.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )

    # RBAC Enforcement: Only Admin can close
    if payload.status.upper() == "CLOSED" and current_user.role.name != "Security Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Security Admin can close alerts."
        )

    try:
        updated_alert = AlertService.update_alert_status(
            db=db,
            alert_id=alert_id,
            new_status=payload.status,
            performed_by=current_user.id,
            reason=payload.reason
        )
        return updated_alert
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.patch("/{alert_id}/assign", response_model=AlertRead)
def assign_alert_endpoint(
    alert_id: int,
    payload: AlertAssign,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin"]))
):
    """
    Assign an alert to an analyst. Restricted to Security Admin.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )

    if payload.assigned_to is not None:
        # Check if user exists
        assigned_user = db.get(User, payload.assigned_to)
        if not assigned_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Assigned user with ID {payload.assigned_to} does not exist"
            )

    try:
        updated_alert = AlertService.assign_alert(
            db=db,
            alert_id=alert_id,
            assigned_to=payload.assigned_to,
            performed_by=current_user.id
        )
        return updated_alert
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/{alert_id}/history", response_model=List[AlertHistoryRead])
def get_alert_history_endpoint(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Retrieve history log for an alert.
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found"
        )

    stmt = select(AlertHistory).where(AlertHistory.alert_id == alert_id).order_by(desc(AlertHistory.timestamp))
    return db.execute(stmt).scalars().all()
