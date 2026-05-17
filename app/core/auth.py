"""
Unified auth helpers — single source of truth for all API modules.

Usage:
  from core.auth import get_user, require_admin, verify_team_membership, verify_ownership
"""

from fastapi import Request, HTTPException


def get_user(r: Request) -> str:
    """Extract authenticated user_id from request state. Raises 401 if missing."""
    token = getattr(r.state, "token", None)
    if not token or token == "anonymous":
        raise HTTPException(401, "Authentication required")
    return token


def get_user_teams(r: Request) -> str:
    """Return comma-separated team IDs the user belongs to."""
    try:
        from database.user_mgmt import get_user_teams as _get
        return _get(get_user(r)) or ""
    except Exception:
        return ""


def require_admin(r: Request):
    """Raise 403 if the authenticated user is not an admin."""
    user_id = get_user(r)
    from database.connection import get_connection
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM teams WHERE creator_user_id = ?",
        (user_id,),
    ).fetchone()
    is_admin = row and row["cnt"] > 0
    if not is_admin:
        existing = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "is_admin" in existing:
            admin_row = conn.execute(
                "SELECT is_admin FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
            is_admin = admin_row and admin_row["is_admin"]
    conn.close()
    if not is_admin:
        raise HTTPException(403, "Admin privileges required")


def verify_team_membership(team_id: str, user_id: str):
    """Raise 403 if user is not a member of the given team. Result cached 60s."""
    if not team_id:
        return
    from core.cache import cache
    ck = f"team_member:{team_id}:{user_id}"
    is_member = cache.get(ck)
    if is_member is None:
        from database.connection import get_connection
        conn = get_connection()
        row = conn.execute(
            "SELECT 1 FROM team_users WHERE team_id=? AND user_id=?",
            (team_id, user_id),
        ).fetchone()
        conn.close()
        is_member = bool(row)
        cache.set(ck, is_member, ttl=60)
    if not is_member:
        raise HTTPException(403, "Not a member of this team")


def verify_ownership(resource: dict, user_id: str, user_teams: str):
    """Check if user owns the resource or is in the owning team. Raises 403 if not.
    resource: dict with optional keys 'user_id', 'team_ids' (comma-separated), 'team_id' (single)
    """
    if not resource:
        raise HTTPException(404, "Resource not found")
    # User owns it directly
    if resource.get("user_id") == user_id or not resource.get("user_id"):
        return
    # Check team_ids (comma-separated)
    team_ids = resource.get("team_ids", "")
    if not team_ids:
        team_ids = resource.get("team_id", "")
    if team_ids and user_teams:
        for t in team_ids.split(","):
            t = t.strip()
            if t and t in user_teams.split(","):
                return
    raise HTTPException(403, "Access denied")


def get_followed_team_ids(user_id: str) -> list:
    """Return list of team IDs the user follows or belongs to."""
    from database.connection import get_connection
    conn = get_connection()
    rows = conn.execute(
        "SELECT team_id FROM user_followed_teams WHERE user_id=?",
        (user_id,),
    ).fetchall()
    # Also include teams where the user is a member
    member_rows = conn.execute(
        "SELECT team_id FROM team_users WHERE user_id=?",
        (user_id,),
    ).fetchall()
    conn.close()
    ids = {r[0] for r in rows}
    ids.update(r[0] for r in member_rows)
    return list(ids)
