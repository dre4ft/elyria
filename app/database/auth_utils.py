"""Shared auth helpers — single source of truth for user extraction."""

from fastapi import Request, HTTPException


def get_auth_user(r: Request) -> str:
    """Extract authenticated user_id from request state. Raises 401 if missing."""
    token = getattr(r.state, "token", None)
    if not token or token == "anonymous":
        raise HTTPException(401, "Authentication required")
    return token


def get_auth_user_teams(r: Request) -> str:
    """Return comma-separated team IDs the user belongs to."""
    try:
        from database.user_mgmt import get_user_teams
        return get_user_teams(get_auth_user(r)) or ""
    except Exception:
        return ""
