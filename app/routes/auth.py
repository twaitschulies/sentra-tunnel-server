"""
Authentication Routes

Login, logout, and session management.
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Response, HTTPException, Depends, Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from passlib.hash import bcrypt

from ..models.user import LoginRequest, LoginResponse, User
from ..models.database import get_user_by_username, log_audit

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory session storage (use Redis in production)
sessions = {}


def get_session_expiry(remember_me: bool = False) -> datetime:
    """Get session expiry time."""
    if remember_me:
        return datetime.utcnow() + timedelta(days=30)
    return datetime.utcnow() + timedelta(hours=8)


async def get_current_user(session_id: Optional[str] = Cookie(None)) -> Optional[dict]:
    """
    Get current user from session.

    Returns None if not authenticated.
    """
    if not session_id or session_id not in sessions:
        return None

    session = sessions[session_id]

    # Check expiry
    if datetime.utcnow() > session['expires_at']:
        del sessions[session_id]
        return None

    return session['user']


async def require_auth(session_id: Optional[str] = Cookie(None)) -> dict:
    """
    Require authentication.

    Raises HTTPException if not authenticated.
    """
    user = await get_current_user(session_id)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


async def require_admin(user: dict = Depends(require_auth)) -> dict:
    """
    Require admin role.

    Raises HTTPException if not admin.
    """
    if user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@router.post("/login")
async def login(request: Request, login_data: LoginRequest, response: Response):
    """
    Authenticate user and create session.

    Returns:
        LoginResponse with session info
    """
    username = login_data.username.lower().strip()
    password = login_data.password

    # Get user from database
    user = await get_user_by_username(username)

    if not user:
        await log_audit(
            action="login_failed",
            details=f"Unknown user: {username}",
            ip_address=request.client.host
        )
        return LoginResponse(success=False, error="Invalid credentials")

    # Verify password
    if not bcrypt.verify(password, user['password_hash']):
        await log_audit(
            action="login_failed",
            user_id=user['id'],
            details="Invalid password",
            ip_address=request.client.host
        )
        return LoginResponse(success=False, error="Invalid credentials")

    # Create session
    session_id = f"sess_{uuid.uuid4().hex}"
    expires_at = get_session_expiry(login_data.remember_me)

    sessions[session_id] = {
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user.get('email'),
            'role': user['role']
        },
        'expires_at': expires_at,
        'ip_address': request.client.host
    }

    # Set session cookie
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,  # Set to False for local development
        samesite="lax",
        max_age=int((expires_at - datetime.utcnow()).total_seconds())
    )

    # Log success
    await log_audit(
        action="login_success",
        user_id=user['id'],
        ip_address=request.client.host
    )

    logger.info(f"User logged in: {username}")

    return LoginResponse(
        success=True,
        user=User(
            id=user['id'],
            username=user['username'],
            email=user.get('email'),
            role=user['role']
        ),
        session_id=session_id
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    session_id: Optional[str] = Cookie(None)
):
    """Log out and clear session."""
    if session_id and session_id in sessions:
        user = sessions[session_id].get('user', {})
        del sessions[session_id]

        await log_audit(
            action="logout",
            user_id=user.get('id'),
            ip_address=request.client.host
        )

    response.delete_cookie("session_id")

    return {"success": True}


@router.get("/me")
async def get_current_user_info(user: dict = Depends(require_auth)):
    """Get current user information."""
    return User(**user)


@router.get("/check")
async def check_auth(session_id: Optional[str] = Cookie(None)):
    """Check if user is authenticated."""
    user = await get_current_user(session_id)
    return {
        "authenticated": user is not None,
        "user": User(**user) if user else None
    }
