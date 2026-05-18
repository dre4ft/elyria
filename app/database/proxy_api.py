# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""Proxy CRUD + user favorite proxy selection."""

import json, uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException
from database.connection import get_connection

app = APIRouter(prefix="/api/proxies", tags=["proxies"])

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def _conn():
    return get_connection()

def init():
    c = _conn()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS proxies (id INTEGER PRIMARY KEY, proxy_id TEXT UNIQUE, name TEXT, url TEXT NOT NULL,
            team_ids TEXT DEFAULT '', user_id TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS user_favorite_proxy (user_id TEXT PRIMARY KEY, proxy_id TEXT, enabled INTEGER DEFAULT 1);
    """)
    try:
        c.execute("ALTER TABLE user_favorite_proxy ADD COLUMN enabled INTEGER DEFAULT 1")
    except:
        pass
    c.commit(); c.close()
init()

from database.auth_utils import get_auth_user

@app.get("")
def list_proxies(request: Request):
    uid = get_auth_user(request)
    # Gather user's teams for team-scoped proxies
    c = _conn()
    teams = [r[0] for r in c.execute("SELECT team_id FROM user_followed_teams WHERE user_id=?", (uid,)).fetchall()]
    q = "SELECT * FROM proxies WHERE user_id=? OR user_id=''"
    args = [uid]
    for t in teams:
        q += " OR team_ids LIKE ?"
        args.append(f"%{t}%")
    q += " ORDER BY name"
    rows = c.execute(q, args).fetchall()
    c.close()
    return [dict(r) for r in rows]

@app.post("")
async def create_proxy(request: Request):
    body = await request.json()
    name = body.get("name","").strip()
    url = body.get("url","").strip()
    if not url: raise HTTPException(400, "url required")
    c = _conn()
    pid = str(uuid.uuid4())
    c.execute("INSERT INTO proxies (proxy_id,name,url,user_id,team_ids,created_at) VALUES(?,?,?,?,?,?)",
              (pid, name or url, url, get_auth_user(request), body.get("team_ids",""), _now()))
    c.commit(); c.close()
    return {"proxy_id": pid}

@app.delete("/{proxy_id}")
def delete_proxy(proxy_id: str, request: Request):
    c = _conn(); c.execute("DELETE FROM proxies WHERE proxy_id=? AND user_id=?", (proxy_id, get_auth_user(request))); c.commit(); c.close()
    return {"status":"deleted"}

@app.get("/favorite")
def get_favorite(request: Request):
    uid = get_auth_user(request)
    c = _conn()
    row = c.execute("SELECT p.* FROM user_favorite_proxy u JOIN proxies p ON u.proxy_id=p.proxy_id WHERE u.user_id=?", (uid,)).fetchone()
    c.close()
    return {"proxy": dict(row) if row else None}

@app.put("/favorite")
async def set_favorite(request: Request):
    body = await request.json()
    uid = get_auth_user(request)
    proxy_id = body.get("proxy_id")  # None or "" = clear favorite
    c = _conn()
    if proxy_id:
        # Preserve existing enabled flag if present
        existing = c.execute("SELECT enabled FROM user_favorite_proxy WHERE user_id=?", (uid,)).fetchone()
        keep_enabled = existing[0] if existing else 1
        c.execute("INSERT OR REPLACE INTO user_favorite_proxy (user_id,proxy_id,enabled) VALUES(?,?,?)", (uid, proxy_id, keep_enabled))
    else:
        c.execute("DELETE FROM user_favorite_proxy WHERE user_id=?", (uid,))
    c.commit(); c.close()
    return {"status":"ok"}

@app.get("/toggle")
def get_proxy_toggle(request: Request):
    uid = get_auth_user(request)
    c = _conn()
    row = c.execute("SELECT enabled FROM user_favorite_proxy WHERE user_id=?", (uid,)).fetchone()
    c.close()
    return {"enabled": bool(row[0]) if row else False}

@app.put("/toggle")
async def set_proxy_toggle(request: Request):
    body = await request.json()
    uid = get_auth_user(request)
    enabled = 1 if body.get("enabled", True) else 0
    c = _conn()
    # Only update if a row exists (proxy must be set as favorite first)
    row = c.execute("SELECT user_id FROM user_favorite_proxy WHERE user_id=?", (uid,)).fetchone()
    if row:
        c.execute("UPDATE user_favorite_proxy SET enabled=? WHERE user_id=?", (enabled, uid))
    else:
        # No favorite proxy yet — store toggle intent for when one is set
        c.execute("INSERT INTO user_favorite_proxy (user_id,proxy_id,enabled) VALUES(?,'',?)", (uid, enabled))
    c.commit(); c.close()
    return {"enabled": bool(enabled)}
