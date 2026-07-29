from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.models.user import User
from app.models.role import Role
from app.models.audit_log import AuditLog
from app.schemas.user import UserRead, UserUpdate, AuditLogRead
from app.services.auth_service import get_current_active_user, RoleChecker, log_audit_event
from app.core.security import get_password_hash

router = APIRouter()

@router.get("/me", response_model=UserRead)
def read_user_me(current_user: User = Depends(get_current_active_user)):
    """
    Get current logged-in user profile.
    """
    return current_user

@router.get("/", response_model=List[UserRead])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin_user: User = Depends(RoleChecker(["Security Admin"]))
):
    """
    Retrieve all registered users. Restricted to Security Admin role.
    """
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@router.get("/audit-logs", response_model=List[AuditLogRead])
def read_audit_logs(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin_user: User = Depends(RoleChecker(["Security Admin"]))
):
    """
    Retrieve all system audit logs. Restricted to Security Admin role.
    Logs are returned in descending order (newest first).
    """
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    return logs

@router.put("/{user_id}", response_model=UserRead)
def update_user_by_admin(
    user_id: int,
    user_in: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(RoleChecker(["Security Admin"]))
):
    """
    Update a user's details, role, or status. Restricted to Security Admin role.
    """
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Process updates
    update_data = user_in.model_dump(exclude_unset=True)
    
    # Resolve role name if provided
    if "role_name" in update_data and update_data["role_name"]:
        role_name = update_data["role_name"]
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{role_name}' does not exist."
            )
        db_user.role_id = role.id
        del update_data["role_name"]
        
    if "password" in update_data and update_data["password"]:
        db_user.hashed_password = get_password_hash(update_data["password"])
        del update_data["password"]
        
    for field, value in update_data.items():
        setattr(db_user, field, value)
        
    db.commit()
    db.refresh(db_user)
    
    # Log update event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        user_id=admin_user.id,
        action="USER_UPDATED",
        details=f"Admin {admin_user.email} updated details for user ID: {db_user.id} ({db_user.email})",
        ip_address=client_ip
    )
    
    return db_user
