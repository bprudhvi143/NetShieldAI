from typing import List, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config.settings import settings
from app.core.security import get_password_hash, decode_access_token
from app.db.postgres import get_db
from app.models.user import User
from app.models.role import Role
from app.models.audit_log import AuditLog
from app.schemas.user import UserCreate

# OAuth2 scheme definition. Points to the login endpoint.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)

def log_audit_event(
    db: Session,
    user_id: Optional[int],
    action: str,
    details: Optional[str] = None,
    ip_address: Optional[str] = None
) -> AuditLog:
    """
    Utility service to create and commit an audit log entry in PostgreSQL.
    """
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def get_user_by_email(db: Session, email: str) -> User | None:
    """
    Query PostgreSQL to retrieve a user by email address.
    """
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user_in: UserCreate) -> User:
    """
    Resolve requested role by name, hash password, and create a user.
    """
    # Resolve the database role by name
    role = db.query(Role).filter(Role.name == user_in.role_name).first()
    if not role:
        # Fallback default role
        role = db.query(Role).filter(Role.name == "Security Analyst").first()
        if not role:
            # Emergency fallback: if roles table is not seeded yet, create Security Analyst role
            role = Role(name="Security Analyst", description="Security operations team member")
            db.add(role)
            db.commit()
            db.refresh(role)

    db_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role_id=role.id,
        is_active=user_in.is_active
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Log user registration audit event
    log_audit_event(
        db=db,
        user_id=db_user.id,
        action="USER_REGISTERED",
        details=f"Registered user: {db_user.email} with role: {role.name}"
    )
    
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> User | None:
    """
    Authenticate a user by email and password.
    Returns the User object if successful, None otherwise.
    """
    from app.core.security import verify_password
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def get_current_user(
    db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)
) -> User:
    """
    FastAPI dependency to retrieve the currently logged-in user from the JWT token.
    Raises 401 Unauthorized exception if verification fails.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
    
    email: str = payload.get("sub")
    if email is None:
        raise credentials_exception
        
    user = get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Dependency to verify that the logged-in user account is active.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="Inactive user account"
        )
    return current_user

class RoleChecker:
    """
    FastAPI dependency builder to enforce role-based access control.
    Example: Depends(RoleChecker(["Security Admin", "Security Analyst"]))
    """
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role.name not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action"
            )
        return current_user
