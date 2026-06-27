"""Vulnerable FastAPI app for IAST verification."""
from fastapi import FastAPI, Query, Depends
from fastapi.security import HTTPBearer
import sqlite3
import os
import subprocess
import pickle
import yaml

app = FastAPI()
security = HTTPBearer()


# ── SQL Injection (user input → db.execute without sanitization) ──
@app.get("/api/users")
def get_users(search: str = Query("")):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # TAINT: search flows directly into execute() — SQLi
    cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{search}%'")
    rows = cursor.fetchall()
    conn.close()
    return {"users": rows}


# ── Command Injection ──
@app.get("/api/ping")
def ping(host: str = Query("localhost")):
    # TAINT: host flows into subprocess.run — command injection
    result = subprocess.run(f"ping -c 1 {host}", shell=True,
                           capture_output=True, text=True)
    return {"output": result.stdout}


# ── Path traversal ──
@app.get("/api/files")
def read_file(filename: str = Query("")):
    # TAINT: filename from query param directly used in open()
    with open(filename, 'r') as f:
        content = f.read()
    return {"content": content}


# ── Deserialization (pickle) ──
@app.post("/api/load")
def load_data(data: bytes):
    # TAINT: data flows to pickle.loads — RCE
    obj = pickle.loads(data)
    return {"result": str(obj)}


# ── SSRF ──
@app.get("/api/fetch")
def fetch_url(url: str = Query("")):
    import requests
    # TAINT: url from user → requests.get — SSRF
    resp = requests.get(url, timeout=5)
    return {"status": resp.status_code, "body": resp.text[:200]}


# ── YAML deserialization ──
@app.post("/api/config")
def load_config(config: str):
    # TAINT: config → yaml.load without SafeLoader — RCE
    obj = yaml.load(config)
    return {"config": str(obj)}


# ── Auth-bypassable admin endpoint ──
@app.get("/api/admin/users")
def admin_users():
    # TAINT: no auth check — should require authentication
    return {"users": [{"id": 1, "name": "admin", "role": "superadmin"}]}


# ── IDOR-prone endpoint ──
@app.get("/api/orders/{order_id}")
def get_order(order_id: int):
    # TAINT: order_id used directly without ownership check
    return {"order_id": order_id, "user_id": 1, "items": ["secret_item"]}


# ── Safe endpoint (should NOT be flagged) ──
@app.get("/api/health")
def health():
    return {"status": "ok"}


# ── XSS ──
@app.get("/api/search")
def search_html(q: str = Query("")):
    # TAINT: q reflected without escaping
    return {"results": f"<html><body>Results for: {q}</body></html>"}
