# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Team management + User Hub API.
Decentralized governance: any user can create teams, join requests require 80% approval.
"""

from core.cache import cache as _cache
from core.audit import info as _audit


def _invalidate_team_caches(team_id: str, user_id: str = ""):
    """Invalidate cached team membership and tree data on member changes."""
    _cache.invalidate_prefix(f"team_member:{team_id}:")
    if user_id:
        _cache.invalidate_prefix(f"tree:{user_id}:")
        _cache.invalidate(f"team_member:{team_id}:{user_id}")

import json, uuid, math
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from database.connection import get_connection

app = APIRouter(prefix="/api", tags=["teams"])

def _now(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
def _conn():
    return get_connection()
from database.auth_utils import get_auth_user

def init_teams():
    c = _conn()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS teams (id INTEGER PRIMARY KEY, team_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
            creator_user_id TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS team_users (team_id TEXT NOT NULL, user_id TEXT NOT NULL,
            PRIMARY KEY(team_id, user_id), FOREIGN KEY(team_id) REFERENCES teams(team_id));
        CREATE TABLE IF NOT EXISTS pending_team_requests (team_id TEXT NOT NULL, user_id TEXT NOT NULL,
            validators TEXT DEFAULT '[]', needed_validator INTEGER DEFAULT 1,
            PRIMARY KEY(team_id, user_id), FOREIGN KEY(team_id) REFERENCES teams(team_id));
        CREATE TABLE IF NOT EXISTS user_followed_teams (user_id TEXT NOT NULL, team_id TEXT NOT NULL,
            PRIMARY KEY(user_id, team_id));
    """)
    # Migration: add encrypted_team_key to teams
    try: c.execute("ALTER TABLE teams ADD COLUMN encrypted_team_key TEXT NOT NULL DEFAULT ''")
    except: pass
    # Migrations for team integration
    for tbl, col in [("folders", "team_id"), ("saved_requests", "team_id"), ("workflow_graphs", "team_id"), ("pentest_scan_profiles", "team_ids")]:
        try: c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} TEXT DEFAULT ''")
        except: pass
    c.commit(); c.close()
init_teams()


# ── Hub ──
@app.get("/user/hub")
def user_hub(request: Request):
    uid = get_auth_user(request)
    c = _conn()
    # Teams the user belongs to
    teams = c.execute("SELECT t.*, (SELECT COUNT(*) FROM team_users WHERE team_id=t.team_id) as member_count FROM teams t JOIN team_users tu ON t.team_id=tu.team_id WHERE tu.user_id=?", (uid,)).fetchall()
    teams_data = []
    for t in teams:
        members = c.execute("SELECT tu.user_id, u.username FROM team_users tu LEFT JOIN users u ON tu.user_id=u.user_id WHERE tu.team_id=?", (t["team_id"],)).fetchall()
        pendings = c.execute("SELECT * FROM pending_team_requests WHERE team_id=?", (t["team_id"],)).fetchall()
        teams_data.append({
            "team_id": t["team_id"], "name": t["name"], "creator": t["creator_user_id"],
            "member_count": t["member_count"], "created_at": t["created_at"],
            "members": [{"user_id": m["user_id"], "username": (m["username"] or m["user_id"])} for m in members],
            "pending": [{"user_id": p["user_id"], "validators": json.loads(p["validators"]), "needed": p["needed_validator"]} for p in pendings],
        })
    # User's proxies
    proxies = c.execute("SELECT * FROM proxies WHERE user_id=? OR user_id=''", (uid,)).fetchall()
    fav = c.execute("SELECT proxy_id, enabled FROM user_favorite_proxy WHERE user_id=?", (uid,)).fetchone()
    c.close()
    return {
        "user_id": uid,
        "teams": teams_data,
        "proxies": [dict(p) for p in proxies],
        "favorite_proxy_id": fav["proxy_id"] if fav else None,
        "proxy_enabled": bool(fav["enabled"]) if fav else False,
    }


# ── Teams CRUD ──
@app.post("/teams")
async def create_team(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    if not name: raise HTTPException(400, "name required")
    uid = get_auth_user(request)
    tid = str(uuid.uuid4())
    # Generate team key and wrap it for the creator (BYOK)
    from database.crypto_store import create_team_with_key
    wrapped_key = create_team_with_key(tid, uid)
    c = _conn()
    c.execute("INSERT INTO teams (team_id,name,creator_user_id,created_at,encrypted_team_key) VALUES(?,?,?,?,?)",
              (tid, name, uid, _now(), wrapped_key))
    c.execute("INSERT INTO team_users (team_id,user_id,encrypted_team_key) VALUES(?,?,?)",
              (tid, uid, wrapped_key))
    c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (uid, tid))
    c.commit(); c.close()
    _invalidate_team_caches(tid, uid)
    _audit("team.create", user_id=uid, resource_id=tid, resource_type="team")
    return {"team_id": tid, "name": name}


@app.get("/teams")
def list_my_teams(request: Request):
    uid = get_auth_user(request)
    c = _conn()
    rows = c.execute("SELECT t.*, (SELECT COUNT(*) FROM team_users WHERE team_id=t.team_id) as member_count FROM teams t JOIN team_users tu ON t.team_id=tu.team_id WHERE tu.user_id=?", (uid,)).fetchall()
    c.close()
    return [dict(r) for r in rows]


@app.get("/teams/{team_id}")
def get_team(team_id: str, request: Request):
    uid = get_auth_user(request)
    c = _conn()
    t = c.execute("SELECT * FROM teams WHERE team_id=?", (team_id,)).fetchone()
    if not t: raise HTTPException(404, "Team not found")
    members = c.execute("SELECT tu.user_id, u.username FROM team_users tu LEFT JOIN users u ON tu.user_id=u.user_id WHERE tu.team_id=?", (team_id,)).fetchall()
    is_member = any(m["user_id"] == uid for m in members)
    pendings = []
    if is_member:
        pendings = c.execute("SELECT * FROM pending_team_requests WHERE team_id=?", (team_id,)).fetchall()
    c.close()
    if not is_member:
        return {
            "team_id": t["team_id"], "name": t["name"],
            "member_count": len(members),
            "is_member": False,
        }
    return {
        "team_id": t["team_id"], "name": t["name"], "creator": t["creator_user_id"],
        "created_at": t["created_at"],
        "members": [{"user_id": m["user_id"], "username": (m["username"] or m["user_id"])} for m in members],
        "member_count": len(members),
        "pending": [{"user_id": p["user_id"], "validators": json.loads(p["validators"]), "needed": p["needed_validator"]} for p in pendings],
        "is_member": True,
    }


# ── Join request (silent — no confirmation if team exists) ──
@app.post("/teams/{team_id}/join")
async def request_join(team_id: str, request: Request):
    uid = get_auth_user(request)
    c = _conn()
    t = c.execute("SELECT * FROM teams WHERE team_id=?", (team_id,)).fetchone()
    if not t:
        c.close()
        return {"status": "ok"}  # Silent — don't reveal if team exists
    # Already a member?
    existing = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if existing:
        c.close()
        return {"status": "ok"}  # Already a member, silent
    # Already pending?
    pend = c.execute("SELECT 1 FROM pending_team_requests WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if pend:
        c.close()
        return {"status": "ok"}  # Already pending, silent
    # Calculate needed validators: ceil(80% of current team size)
    member_count = c.execute("SELECT COUNT(*) FROM team_users WHERE team_id=?", (team_id,)).fetchone()[0]
    needed = max(1, math.ceil(member_count * 0.8))
    c.execute("INSERT INTO pending_team_requests (team_id,user_id,validators,needed_validator) VALUES(?,?,?,?)",
              (team_id, uid, "[]", needed))
    c.commit(); c.close()
    return {"status": "ok"}  # Always silent


# ── Validate a pending request (only team members can validate) ──
@app.post("/teams/{team_id}/validate/{target_user_id}")
async def validate_request(team_id: str, target_user_id: str, request: Request):
    uid = get_auth_user(request)
    c = _conn()
    # Check requester is member of the team
    member = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if not member: raise HTTPException(403, "Not a team member")
    # Check pending request exists
    pend = c.execute("SELECT * FROM pending_team_requests WHERE team_id=? AND user_id=?", (team_id, target_user_id)).fetchone()
    if not pend: raise HTTPException(404, "No pending request")
    # Idempotent: add validator
    validators = json.loads(pend["validators"])
    if uid not in validators:
        validators.append(uid)
    c.execute("UPDATE pending_team_requests SET validators=? WHERE team_id=? AND user_id=?",
              (json.dumps(validators), team_id, target_user_id))
    # Check threshold
    if len(validators) >= pend["needed_validator"]:
        # Add member and wrap team key for them (BYOK)
        from database.crypto_store import add_member_team_key, get_team_key
        team_key = get_team_key(uid, team_id)
        if team_key:
            c.execute("INSERT OR IGNORE INTO team_users (team_id,user_id) VALUES(?,?)", (team_id, target_user_id))
            c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (target_user_id, team_id))
            c.execute("DELETE FROM pending_team_requests WHERE team_id=? AND user_id=?", (team_id, target_user_id))
            c.commit()
            _invalidate_team_caches(team_id, target_user_id)
            # Now wrap the team key for the new member
            add_member_team_key(team_id, target_user_id, uid)
        else:
            c.commit()
    c.commit(); c.close()
    _audit("team.member_added", user_id=target_user_id, team_id=team_id, resource_type="team", detail=f"validated by {uid}")
    return {"status": "validated", "validators": len(validators), "needed": pend["needed_validator"],
            "added": len(validators) >= pend["needed_validator"]}


# ── User Hub: quick proxy toggle (also accessible from proxy_api) ──
# ── Followed teams ──
@app.get("/user/followed-teams")
def list_followed(request: Request):
    uid = get_auth_user(request)
    c = _conn()
    # Return teams the user follows, but also auto-include teams they belong to
    member_teams = c.execute("SELECT team_id FROM team_users WHERE user_id=?", (uid,)).fetchall()
    for mt in member_teams:
        c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (uid, mt["team_id"]))
    c.commit()
    rows = c.execute("SELECT t.*, (SELECT COUNT(*) FROM team_users WHERE team_id=t.team_id) as member_count FROM teams t JOIN user_followed_teams f ON t.team_id=f.team_id WHERE f.user_id=?", (uid,)).fetchall()
    c.close()
    return [dict(r) for r in rows]

@app.post("/user/followed-teams/{team_id}")
def follow_team(team_id: str, request: Request):
    uid = get_auth_user(request)
    c = _conn()
    # Must be a member of the team to follow it
    member = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if not member: raise HTTPException(403, "Not a team member")
    c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (uid, team_id))
    c.commit(); c.close()
    return {"status": "ok"}

@app.delete("/user/followed-teams/{team_id}")
def unfollow_team(team_id: str, request: Request):
    uid = get_auth_user(request)
    c = _conn()
    c.execute("DELETE FROM user_followed_teams WHERE user_id=? AND team_id=?", (uid, team_id))
    c.commit(); c.close()
    return {"status": "ok"}


# ── Proxy favorite ──
@app.put("/user/proxy-favorite")
async def set_fav_proxy(request: Request):
    body = await request.json()
    uid = get_auth_user(request)
    pid = body.get("proxy_id")
    c = _conn()
    if pid:
        c.execute("INSERT OR REPLACE INTO user_favorite_proxy (user_id,proxy_id) VALUES(?,?)", (uid, pid))
    else:
        c.execute("DELETE FROM user_favorite_proxy WHERE user_id=?", (uid,))
    c.commit(); c.close()
    return {"status": "ok"}


# ── Remove member + rotate team key ──
@app.delete("/teams/{team_id}/members/{user_id}")
def remove_member(team_id: str, user_id: str, request: Request):
    """Remove a member from the team. Rotates the team key so the removed member can no longer decrypt data."""
    uid = get_auth_user(request)
    c = _conn()
    # Verify requester is a team member
    member = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if not member: raise HTTPException(403, "Not a team member")
    # Verify target is a team member
    target = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, user_id)).fetchone()
    if not target: raise HTTPException(404, "User not in team")
    # Prevent self-removal (use leave endpoint instead)
    if uid == user_id: raise HTTPException(400, "Use leave endpoint to remove yourself")
    # Remove the member
    c.execute("DELETE FROM team_users WHERE team_id=? AND user_id=?", (team_id, user_id))
    c.execute("DELETE FROM user_followed_teams WHERE team_id=? AND user_id=?", (team_id, user_id))
    c.commit()
    _invalidate_team_caches(team_id, user_id)
    remaining = c.execute("SELECT COUNT(*) FROM team_users WHERE team_id=?", (team_id,)).fetchone()[0]
    c.close()
    # Rotate team key — departing member can no longer decrypt
    from database.crypto_store import rotate_team_key
    count = rotate_team_key(team_id, uid)
    _audit("team.member_removed", user_id=uid, team_id=team_id, resource_type="team", detail=f"removed {user_id}, rows={count}")
    return {"status": "removed", "remaining_members": remaining, "rows_re_encrypted": count}


@app.delete("/teams/{team_id}/leave")
def leave_team(team_id: str, request: Request):
    """Leave a team. Rotates the team key so you can no longer decrypt data."""
    uid = get_auth_user(request)
    c = _conn()
    target = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if not target: raise HTTPException(404, "Not a team member")
    c.execute("DELETE FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid))
    c.execute("DELETE FROM user_followed_teams WHERE team_id=? AND user_id=?", (team_id, uid))
    c.commit()
    _invalidate_team_caches(team_id, uid)
    remaining = c.execute("SELECT COUNT(*) FROM team_users WHERE team_id=?", (team_id,)).fetchone()[0]
    c.close()
    # If team still has members, rotate the key
    count = 0
    if remaining > 0:
        from database.crypto_store import rotate_team_key
        # Use any remaining member as the performer (first one found)
        c2 = _conn()
        next_member = c2.execute("SELECT user_id FROM team_users WHERE team_id=? LIMIT 1", (team_id,)).fetchone()
        c2.close()
        if next_member:
            # Temporarily load performer's key
            from database.crypto_store import load_user_key
            count = rotate_team_key(team_id, next_member["user_id"])
    _audit("team.member_left", user_id=uid, team_id=team_id, resource_type="team", detail=f"rows={count}")
    return {"status": "left", "remaining_members": remaining, "rows_re_encrypted": count}
