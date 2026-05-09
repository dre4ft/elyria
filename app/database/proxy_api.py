"""Proxy CRUD + user favorite proxy selection."""

import json, uuid, sqlite3
from datetime import datetime, timezone
from fastapi import APIRouter, Request, HTTPException

app = APIRouter(prefix="/api/proxies", tags=["proxies"])
DB = "database.db"

def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def _conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init():
    c = _conn()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS proxies (id INTEGER PRIMARY KEY, proxy_id TEXT UNIQUE, name TEXT, url TEXT NOT NULL,
            team_ids TEXT DEFAULT '', user_id TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS user_favorite_proxy (user_id TEXT PRIMARY KEY, proxy_id TEXT);
    """)
    c.commit(); c.close()
init()

def _get_user(r: Request): return getattr(r.state, "token", "anonymous")

@app.get("")
def list_proxies(request: Request):
    uid = _get_user(request)
    c = _conn()
    rows = c.execute("SELECT * FROM proxies WHERE user_id=? OR user_id='' ORDER BY name", (uid,)).fetchall()
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
              (pid, name or url, url, _get_user(request), body.get("team_ids",""), _now()))
    c.commit(); c.close()
    return {"proxy_id": pid}

@app.delete("/{proxy_id}")
def delete_proxy(proxy_id: str, request: Request):
    c = _conn(); c.execute("DELETE FROM proxies WHERE proxy_id=? AND user_id=?", (proxy_id, _get_user(request))); c.commit(); c.close()
    return {"status":"deleted"}

@app.get("/favorite")
def get_favorite(request: Request):
    uid = _get_user(request)
    c = _conn()
    row = c.execute("SELECT p.* FROM user_favorite_proxy u JOIN proxies p ON u.proxy_id=p.proxy_id WHERE u.user_id=?", (uid,)).fetchone()
    c.close()
    return {"proxy": dict(row) if row else None}

@app.put("/favorite")
async def set_favorite(request: Request):
    body = await request.json()
    uid = _get_user(request)
    proxy_id = body.get("proxy_id")  # None or "" = clear favorite
    c = _conn()
    if proxy_id:
        c.execute("INSERT OR REPLACE INTO user_favorite_proxy (user_id,proxy_id) VALUES(?,?)", (uid, proxy_id))
    else:
        c.execute("DELETE FROM user_favorite_proxy WHERE user_id=?", (uid,))
    c.commit(); c.close()
    return {"status":"ok"}
