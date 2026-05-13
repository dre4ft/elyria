"""
Team management + User Hub API.
Decentralized governance: any user can create teams, join requests require 80% approval.
"""

import json, uuid, math
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from database.connection import get_connection

app = APIRouter(prefix="/api", tags=["teams"])

def _now(): return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
def _conn():
    return get_connection()
def _uid(r: Request):
    token = getattr(r.state, "token", None)
    if not token or token == "anonymous":
        raise HTTPException(401, "Authentication required")
    return token

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
    # Migrations for team integration
    for tbl, col in [("folders", "team_id"), ("saved_requests", "team_id"), ("workflow_graphs", "team_id"), ("pentest_scan_profiles", "team_ids")]:
        try: c.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} TEXT DEFAULT ''")
        except: pass
    c.commit(); c.close()
init_teams()


# ── Hub ──
@app.get("/user/hub")
def user_hub(request: Request):
    uid = _uid(request)
    c = _conn()
    # Teams the user belongs to
    teams = c.execute("SELECT t.*, (SELECT COUNT(*) FROM team_users WHERE team_id=t.team_id) as member_count FROM teams t JOIN team_users tu ON t.team_id=tu.team_id WHERE tu.user_id=?", (uid,)).fetchall()
    teams_data = []
    for t in teams:
        members = c.execute("SELECT user_id FROM team_users WHERE team_id=?", (t["team_id"],)).fetchall()
        pendings = c.execute("SELECT * FROM pending_team_requests WHERE team_id=?", (t["team_id"],)).fetchall()
        teams_data.append({
            "team_id": t["team_id"], "name": t["name"], "creator": t["creator_user_id"],
            "member_count": t["member_count"], "created_at": t["created_at"],
            "members": [m["user_id"] for m in members],
            "pending": [{"user_id": p["user_id"], "validators": json.loads(p["validators"]), "needed": p["needed_validator"]} for p in pendings],
        })
    # User's proxies
    proxies = c.execute("SELECT * FROM proxies WHERE user_id=? OR user_id=''", (uid,)).fetchall()
    fav = c.execute("SELECT proxy_id FROM user_favorite_proxy WHERE user_id=?", (uid,)).fetchone()
    c.close()
    return {
        "user_id": uid,
        "teams": teams_data,
        "proxies": [dict(p) for p in proxies],
        "favorite_proxy_id": fav["proxy_id"] if fav else None,
    }


# ── Teams CRUD ──
@app.post("/teams")
async def create_team(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    if not name: raise HTTPException(400, "name required")
    uid = _uid(request)
    tid = str(uuid.uuid4())
    c = _conn()
    c.execute("INSERT INTO teams (team_id,name,creator_user_id,created_at) VALUES(?,?,?,?)", (tid, name, uid, _now()))
    c.execute("INSERT INTO team_users (team_id,user_id) VALUES(?,?)", (tid, uid))
    c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (uid, tid))
    c.commit(); c.close()
    return {"team_id": tid, "name": name}


@app.get("/teams")
def list_my_teams(request: Request):
    uid = _uid(request)
    c = _conn()
    rows = c.execute("SELECT t.*, (SELECT COUNT(*) FROM team_users WHERE team_id=t.team_id) as member_count FROM teams t JOIN team_users tu ON t.team_id=tu.team_id WHERE tu.user_id=?", (uid,)).fetchall()
    c.close()
    return [dict(r) for r in rows]


@app.get("/teams/{team_id}")
def get_team(team_id: str, request: Request):
    uid = _uid(request)
    c = _conn()
    t = c.execute("SELECT * FROM teams WHERE team_id=?", (team_id,)).fetchone()
    if not t: raise HTTPException(404, "Team not found")
    members = c.execute("SELECT user_id FROM team_users WHERE team_id=?", (team_id,)).fetchall()
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
        "members": [m["user_id"] for m in members],
        "member_count": len(members),
        "pending": [{"user_id": p["user_id"], "validators": json.loads(p["validators"]), "needed": p["needed_validator"]} for p in pendings],
        "is_member": True,
    }


# ── Join request (silent — no confirmation if team exists) ──
@app.post("/teams/{team_id}/join")
async def request_join(team_id: str, request: Request):
    uid = _uid(request)
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
    uid = _uid(request)
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
        c.execute("INSERT OR IGNORE INTO team_users (team_id,user_id) VALUES(?,?)", (team_id, target_user_id))
        c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (target_user_id, team_id))
        c.execute("DELETE FROM pending_team_requests WHERE team_id=? AND user_id=?", (team_id, target_user_id))
    c.commit(); c.close()
    return {"status": "validated", "validators": len(validators), "needed": pend["needed_validator"],
            "added": len(validators) >= pend["needed_validator"]}


# ── User Hub: quick proxy toggle (also accessible from proxy_api) ──
# ── Followed teams ──
@app.get("/user/followed-teams")
def list_followed(request: Request):
    uid = _uid(request)
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
    uid = _uid(request)
    c = _conn()
    # Must be a member of the team to follow it
    member = c.execute("SELECT 1 FROM team_users WHERE team_id=? AND user_id=?", (team_id, uid)).fetchone()
    if not member: raise HTTPException(403, "Not a team member")
    c.execute("INSERT OR IGNORE INTO user_followed_teams (user_id,team_id) VALUES(?,?)", (uid, team_id))
    c.commit(); c.close()
    return {"status": "ok"}

@app.delete("/user/followed-teams/{team_id}")
def unfollow_team(team_id: str, request: Request):
    uid = _uid(request)
    c = _conn()
    c.execute("DELETE FROM user_followed_teams WHERE user_id=? AND team_id=?", (uid, team_id))
    c.commit(); c.close()
    return {"status": "ok"}


# ── Proxy favorite ──
@app.put("/user/proxy-favorite")
async def set_fav_proxy(request: Request):
    body = await request.json()
    uid = _uid(request)
    pid = body.get("proxy_id")
    c = _conn()
    if pid:
        c.execute("INSERT OR REPLACE INTO user_favorite_proxy (user_id,proxy_id) VALUES(?,?)", (uid, pid))
    else:
        c.execute("DELETE FROM user_favorite_proxy WHERE user_id=?", (uid,))
    c.commit(); c.close()
    return {"status": "ok"}
