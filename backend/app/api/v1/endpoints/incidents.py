from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, desc
from pydantic import BaseModel, Field

from app.db.postgres import get_db
from app.services.auth_service import RoleChecker
from app.models.user import User
from app.models.incident import Incident
from app.models.incident_history import IncidentHistory
from app.models.alert import Alert
from app.schemas.incident import (
    IncidentCreate,
    IncidentRead,
    IncidentStatusUpdate,
    IncidentAssign,
    IncidentHistoryRead
)
from app.schemas.alert import AlertRead
from app.services.incident_service import IncidentService

router = APIRouter()

class AlertLinkRequest(BaseModel):
    alert_id: int = Field(..., description="The ID of the alert to attach to this incident")

@router.post("/", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
def create_incident_endpoint(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Manually create a new incident. Security Analyst or Security Admin.
    """
    try:
        incident = IncidentService.create_incident(
            db=db,
            title=payload.title,
            description=payload.description,
            priority=payload.priority,
            performed_by=current_user.id
        )
        return incident
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create incident: {str(e)}"
        )

@router.get("/", response_model=List[IncidentRead])
def list_incidents(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    List incidents with filtering and pagination.
    """
    stmt = select(Incident)
    conditions = []

    if status:
        conditions.append(Incident.status == status.upper())
    if priority:
        conditions.append(Incident.priority == priority.upper())
    if assigned_to is not None:
        conditions.append(Incident.assigned_to == assigned_to)

    if conditions:
        stmt = stmt.where(and_(*conditions))

    stmt = stmt.order_by(desc(Incident.created_at)).offset(skip).limit(limit)
    return db.execute(stmt).scalars().all()

@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident_by_id(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Retrieve specific incident details.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found"
        )
    return incident

@router.patch("/{incident_id}/status", response_model=IncidentRead)
def update_incident_status_endpoint(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Transition incident status.
    Note: Transitioning to CLOSED requires 'Security Admin' role.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found"
        )

    # RBAC Enforcement: Only Admin can close
    if payload.status.upper() == "CLOSED" and current_user.role.name != "Security Admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Security Admin can close incidents."
        )

    try:
        updated_incident = IncidentService.update_incident_status(
            db=db,
            incident_id=incident_id,
            new_status=payload.status,
            performed_by=current_user.id,
            reason=payload.reason
        )
        return updated_incident
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.patch("/{incident_id}/assign", response_model=IncidentRead)
def assign_incident_endpoint(
    incident_id: int,
    payload: IncidentAssign,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin"]))
):
    """
    Assign an incident to an analyst. Restricted to Security Admin.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found"
        )

    if payload.assigned_to is not None:
        assigned_user = db.get(User, payload.assigned_to)
        if not assigned_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Assigned user with ID {payload.assigned_to} does not exist"
            )

    try:
        updated_incident = IncidentService.assign_incident(
            db=db,
            incident_id=incident_id,
            assigned_to=payload.assigned_to,
            performed_by=current_user.id
        )
        return updated_incident
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/{incident_id}/alerts", response_model=IncidentRead)
def link_alert_to_incident_endpoint(
    incident_id: int,
    payload: AlertLinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Link a security alert to this incident. Triggers priority escalation on the incident.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found"
        )

    alert = db.get(Alert, payload.alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {payload.alert_id} not found"
        )

    try:
        updated_incident = IncidentService.associate_alert_to_incident(
            db=db,
            incident_id=incident_id,
            alert_id=payload.alert_id,
            performed_by=current_user.id
        )
        return updated_incident
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/{incident_id}/alerts", response_model=List[AlertRead])
def list_incident_alerts(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    List all alerts linked to this incident.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found"
        )

    stmt = select(Alert).where(Alert.incident_id == incident_id).order_by(desc(Alert.created_at))
    return db.execute(stmt).scalars().all()

@router.get("/{incident_id}/history", response_model=List[IncidentHistoryRead])
def get_incident_history_endpoint(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Retrieve history log for an incident.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found"
        )

    stmt = select(IncidentHistory).where(IncidentHistory.incident_id == incident_id).order_by(desc(IncidentHistory.timestamp))
    return db.execute(stmt).scalars().all()
