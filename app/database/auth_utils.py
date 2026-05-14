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


def require_admin(r: Request):
    """Raise 403 if the authenticated user is not an admin."""
    user_id = get_auth_user(r)
    from database.connection import get_connection
    conn = get_connection()
    # Admin = creator of any team, or has is_admin flag
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM teams WHERE creator_user_id = ?",
        (user_id,),
    ).fetchone()
    is_admin = (row and row["cnt"] > 0)
    if not is_admin:
        # Check is_admin column if it exists
        existing = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "is_admin" in existing:
            admin_row = conn.execute(
                "SELECT is_admin FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            is_admin = admin_row and admin_row["is_admin"]
    conn.close()
    if not is_admin:
        raise HTTPException(403, "Admin privileges required")
