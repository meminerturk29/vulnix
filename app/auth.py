"""
Authentication & Session Management Module
- PBKDF2-HMAC-SHA256 password hashing (cross-platform, built-in)
- Cookie-based session management with SQLite storage
- Role-based access control (Admin & Employee)
- Works seamlessly on both Linux (Kali) and Windows
"""

import hashlib
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from app.database import get_db_connection

SESSION_COOKIE_NAME = "vms_session"
SESSION_DURATION_HOURS = 24


def hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        salt_hex, key_hex = stored_hash.split(':')
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return key.hex() == key_hex
    except Exception:
        return False


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user by username and password. Returns user dict or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
    row = cursor.fetchone()
    conn.close()
    if row and verify_password(row["password_hash"], password):
        return dict(row)
    return None


def create_session(user_id: int) -> str:
    """Create a new session for a user, return the session ID."""
    session_id = str(uuid.uuid4())
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    expires = (datetime.now() + timedelta(hours=SESSION_DURATION_HOURS)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO sessions (session_id, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
    """, (session_id, user_id, expires, now_str))
    conn.commit()
    conn.close()
    return session_id


def delete_session(session_id: str):
    """Delete a session (logout)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()


def delete_user_sessions(user_id: int):
    """Delete all sessions for a user (force logout)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def cleanup_expired_sessions():
    """Remove all expired sessions from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (now_str,))
    conn.commit()
    conn.close()


def get_session_user(session_id: str) -> Optional[Dict[str, Any]]:
    """Look up a session and return the associated user, or None if invalid/expired."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        SELECT u.id, u.username, u.full_name, u.email, u.role, u.department, u.is_active
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_id = ? AND s.expires_at > ? AND u.is_active = 1
    """, (session_id, now_str))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


async def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    """FastAPI helper: returns current user dict or None."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    return get_session_user(session_id)


def require_auth(request: Request) -> Optional[Dict[str, Any]]:
    """Helper to verify logged in user. If not logged in, returns None."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    return get_session_user(session_id)
