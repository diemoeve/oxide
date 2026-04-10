"""Authentication utilities."""

import secrets
import time

import bcrypt

from ..storage import (
    create_operator,
    create_session,
    delete_session,
    get_operator_by_username,
    update_operator_login,
)

SESSION_COOKIE_NAME = "oxide_session"
SESSION_TTL = 86400 * 7  # 7 days


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a hash."""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


async def authenticate_user(username: str, password: str) -> dict | None:
    """
    Authenticate a user by username and password.

    Returns the user dict if valid, None otherwise.
    """
    user = await get_operator_by_username(username)
    if not user:
        return None

    if not verify_password(password, user["password_hash"]):
        return None

    return user


async def create_user_session(
    operator_id: str,
    ip_address: str = None,
    user_agent: str = None,
) -> str:
    """Create a new session for a user, returns the session token."""
    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_TTL
    await create_session(token, operator_id, expires_at, ip_address, user_agent)
    await update_operator_login(operator_id)
    return token


async def invalidate_session(token: str):
    """Invalidate a session token."""
    await delete_session(token)


async def ensure_admin_exists():
    """Ensure at least one admin user exists, create default if not."""
    admin = await get_operator_by_username("admin")
    if not admin:
        password_hash = hash_password("oxide")
        await create_operator("admin", password_hash)
        return True
    return False
