from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict

class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleRead(RoleBase):
    id: int
    
    model_config = ConfigDict(from_attributes=True)

class AuditLogBase(BaseModel):
    action: str
    ip_address: Optional[str] = None
    details: Optional[str] = None

class AuditLogRead(AuditLogBase):
    id: int
    user_id: Optional[int] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool = True

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters long")
    role_name: str = Field(default="Security Analyst", description="Role name: Security Admin or Security Analyst")

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    role_name: Optional[str] = None
    is_active: Optional[bool] = None

class UserRead(UserBase):
    id: int
    role_id: int
    role: RoleRead
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
