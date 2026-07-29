from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr

from app.db.postgres import get_db
from app.schemas.user import Token, UserCreate, UserRead
from app.services.auth_service import (
    authenticate_user, 
    create_user, 
    get_user_by_email, 
    log_audit_event
)
from app.core.security import create_access_token
from app.config.settings import settings

router = APIRouter()

class LoginJSONRequest(BaseModel):
    """
    JSON request schema for standard JSON-based login.
    """
    email: EmailStr
    password: str

@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(
    user_in: UserCreate, 
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Register a new user account (Security Analyst or Security Admin).
    Validates input, checks for duplicate email, and hashes password before saving.
    """
    db_user = get_user_by_email(db, email=user_in.email)
    if db_user:
        log_audit_event(
            db=db,
            user_id=None,
            action="REGISTRATION_FAILED",
            details=f"Attempted to register duplicate email: {user_in.email}",
            ip_address=request.client.host if request.client else None
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )
    return create_user(db=db, user_in=user_in)

@router.post("/login", response_model=Token)
def login_access_token_form(
    request: Request,
    db: Session = Depends(get_db), 
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """
    OAuth2 compatible token login, accepts form-encoded data.
    Required for the Swagger UI 'Authorize' lock icon.
    """
    user = authenticate_user(db, email=form_data.username, password=form_data.password)
    client_ip = request.client.host if request.client else None
    
    if not user:
        log_audit_event(
            db=db,
            user_id=None,
            action="LOGIN_FAILED",
            details=f"Invalid password or email: {form_data.username}",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password."
        )
    elif not user.is_active:
        log_audit_event(
            db=db,
            user_id=user.id,
            action="LOGIN_FAILED",
            details=f"Attempted login to inactive user: {user.email}",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account."
        )
    
    # Log successful login
    log_audit_event(
        db=db,
        user_id=user.id,
        action="LOGIN_SUCCESS",
        details=f"User logged in via OAuth2 Form: {user.email}",
        ip_address=client_ip
    )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user.email, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login-json", response_model=Token)
def login_access_token_json(
    credentials: LoginJSONRequest, 
    request: Request,
    db: Session = Depends(get_db)
):
    """
    JSON-based login endpoint. Ideal for React/Vite client integrations.
    """
    user = authenticate_user(db, email=credentials.email, password=credentials.password)
    client_ip = request.client.host if request.client else None
    
    if not user:
        log_audit_event(
            db=db,
            user_id=None,
            action="LOGIN_FAILED",
            details=f"Invalid password or email: {credentials.email}",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password."
        )
    elif not user.is_active:
        log_audit_event(
            db=db,
            user_id=user.id,
            action="LOGIN_FAILED",
            details=f"Attempted login to inactive user: {user.email}",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account."
        )
    
    # Log successful login
    log_audit_event(
        db=db,
        user_id=user.id,
        action="LOGIN_SUCCESS",
        details=f"User logged in via JSON: {user.email}",
        ip_address=client_ip
    )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user.email, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
