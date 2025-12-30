"""
User Models

Pydantic models for user data validation.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime


class UserBase(BaseModel):
    """Base user model."""
    username: str
    email: Optional[str] = None


class UserCreate(UserBase):
    """Model for creating a user."""
    password: str = Field(..., min_length=6)
    role: str = 'operator'


class UserUpdate(BaseModel):
    """Model for updating a user."""
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None


class User(UserBase):
    """Full user model (without password)."""
    id: int
    role: str
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserWithShops(User):
    """User model with accessible shops."""
    shops: List[dict] = []


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str
    remember_me: bool = False


class LoginResponse(BaseModel):
    """Login response model."""
    success: bool
    user: Optional[User] = None
    session_id: Optional[str] = None
    error: Optional[str] = None


class SessionInfo(BaseModel):
    """Session information."""
    session_id: str
    user_id: int
    username: str
    role: str
    expires_at: str
