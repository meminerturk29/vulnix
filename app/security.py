"""
VULNIX Enterprise Defensive Hardening & Security Guard
- Brute-force & Credential Stuffing Prevention (Rate Limiter / Account Lockout)
- Safe File Upload Sanitizer & Path Traversal Prevention
- HTTP Security Headers Enforcement
"""

import time
import os
import re
from typing import Tuple, Dict, List
from fastapi import Request, HTTPException, UploadFile

# --- 1. LOGIN BRUTE FORCE & RATE LIMITING ---
# In-memory tracking of failed login attempts
# Structure: key -> List[timestamps]
_FAILED_ATTEMPTS: Dict[str, List[float]] = {}
_LOCKOUT_TRACKER: Dict[str, float] = {}

MAX_FAILED_ATTEMPTS = 5         # Maximum allowed failures before lockout
ATTEMPT_WINDOW_SECONDS = 300     # 5 minutes window
LOCKOUT_DURATION_SECONDS = 900   # 15 minutes lockout duration


def _get_rate_limit_key(client_ip: str, username: str) -> str:
    cleaned_ip = client_ip.strip() if client_ip else "unknown"
    cleaned_user = username.strip().lower() if username else "anonymous"
    return f"{cleaned_ip}:{cleaned_user}"


def check_login_rate_limit(client_ip: str, username: str) -> Tuple[bool, str]:
    """
    Checks if a login attempt is permitted.
    Returns (allowed: bool, message: str)
    """
    key = _get_rate_limit_key(client_ip, username)
    now = time.time()

    # Check if currently locked out
    lockout_until = _LOCKOUT_TRACKER.get(key, 0)
    if now < lockout_until:
        remaining_seconds = int(lockout_until - now)
        remaining_minutes = max(1, (remaining_seconds + 59) // 60)
        return False, f"Too many failed login attempts. Account temporarily locked for {remaining_minutes} minute(s) to prevent brute-force attacks."

    # Filter out attempts outside the observation window
    attempts = _FAILED_ATTEMPTS.get(key, [])
    attempts = [t for t in attempts if now - t < ATTEMPT_WINDOW_SECONDS]
    _FAILED_ATTEMPTS[key] = attempts

    if len(attempts) >= MAX_FAILED_ATTEMPTS:
        # Trigger lockout
        _LOCKOUT_TRACKER[key] = now + LOCKOUT_DURATION_SECONDS
        _FAILED_ATTEMPTS[key] = []
        return False, "Too many failed login attempts. Account temporarily locked for 15 minutes."

    return True, ""


def record_login_failure(client_ip: str, username: str):
    """Records a failed authentication attempt."""
    key = _get_rate_limit_key(client_ip, username)
    now = time.time()
    if key not in _FAILED_ATTEMPTS:
        _FAILED_ATTEMPTS[key] = []
    _FAILED_ATTEMPTS[key].append(now)


def record_login_success(client_ip: str, username: str):
    """Clears failed authentication records on successful login."""
    key = _get_rate_limit_key(client_ip, username)
    _FAILED_ATTEMPTS.pop(key, None)
    _LOCKOUT_TRACKER.pop(key, None)


# --- 2. SECURE FILE UPLOAD VALIDATION & SANITIZATION ---
SAFE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".pdf", ".txt", ".xml", ".log"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".py", ".pyw", ".ps1",
    ".php", ".phtml", ".js", ".vbs", ".html", ".htm",
    ".dll", ".so", ".jar", ".war", ".jsp", ".asp", ".aspx"
}


def sanitize_filename(filename: str) -> str:
    """
    Strips directory paths, null bytes, and non-whitelisted characters.
    Prevents Path Traversal (e.g. ../../etc/passwd).
    """
    if not filename:
        return "unnamed_file"
    # Take only the base name (prevents directory traversal)
    base = os.path.basename(filename)
    # Remove null bytes
    base = base.replace("\0", "")
    # Allow alphanumeric, dot, underscore, dash
    clean = re.sub(r"[^a-zA-Z0-9._-]", "_", base)
    # Ensure there is a safe name
    clean = clean.lstrip(".")
    return clean or "uploaded_attachment"


def validate_uploaded_file(upload_file: UploadFile, max_size_mb: int = 15) -> str:
    """
    Validates uploaded file against path traversal and dangerous executable extensions.
    Returns the sanitized safe filename.
    Raises HTTPException(400) if validation fails.
    """
    if not upload_file or not upload_file.filename:
        return ""

    safe_name = sanitize_filename(upload_file.filename)
    _, ext = os.path.splitext(safe_name.lower())

    if ext in DANGEROUS_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Security Alert: Executable file upload rejected ({ext}). Only verified documents and images are permitted."
        )

    if ext not in SAFE_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format: {ext}. Allowed: PNG, JPG, WEBP, PDF, TXT, XML."
        )

    return safe_name
