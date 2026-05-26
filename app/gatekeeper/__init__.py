# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Gatekeeper — opaque authentication wall.

All requests behind the gate return 404 until a valid key is provided.
The key is stored in enterprise/.gate_key (not tracked by git).
Validation is constant-time (bit-by-bit via secrets.compare_digest).

Flow:
  1. GET /gate → serves the gate login page
  2. POST /gate {"key": "..."} → validates key, sets signed cookie (24h TTL)
  3. All other routes → 404 if no valid gate cookie

Config:
  gatekeeper.enabled = "0" → disabled (default)
  gatekeeper.enabled = "1" → gatekeeper active, blocks all requests without valid cookie
"""

import hashlib
import hmac
import os
import re
import secrets
import time

from fastapi import Request, APIRouter
from fastapi.responses import JSONResponse, HTMLResponse


GATE_COOKIE = "elyria_gate"
GATE_TTL = 86400  # 24 hours
KEY_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _load_gate_key() -> str:
    """Read the gate key from enterprise/.gate_key. Falls back to env var."""
    env_key = os.getenv("ELYRIA_GATE_KEY", "")
    if env_key and KEY_PATTERN.match(env_key):
        return env_key

    # Try file in app/gatekeeper/
    key_path = os.path.join(os.path.dirname(__file__), ".gate_key")
    if os.path.isfile(key_path):
        with open(key_path, "r", encoding="utf-8-sig") as f:
            key = f.read().strip().lstrip("﻿")
            if KEY_PATTERN.match(key):
                return key

    return ""


GATE_KEY = _load_gate_key()


def _sign_gate_token(gate_key: str) -> str:
    """Sign the gate key with HMAC + timestamp for the cookie."""
    ts = str(int(time.time()))
    server_key = _get_server_secret()
    payload = f"{gate_key}.{ts}"
    sig = hmac.new(server_key, payload.encode(), "sha256").hexdigest()
    return f"{payload}.{sig}"


GATE_DEADLINE_MS = 1.30


def _deadline_exceeded(start: float) -> bool:
    return (time.perf_counter() - start) * 1000 > GATE_DEADLINE_MS


def _verify_gate_token(token: str, gate_key: str) -> bool:
    """Verify a gate cookie token. Hard-capped at 1.30ms to prevent timing attacks."""
    t0 = time.perf_counter()
    try:
        parts = token.split(".")
        if _deadline_exceeded(t0):
            return False
        if len(parts) != 3:
            return False
        key_part, ts_str, sig = parts

        if not secrets.compare_digest(key_part, gate_key):
            return False
        if _deadline_exceeded(t0):
            return False

        ts = int(ts_str)
        if time.time() - ts > GATE_TTL:
            return False

        server_key = _get_server_secret()
        expected = hmac.new(server_key, f"{key_part}.{ts_str}".encode(), "sha256").hexdigest()
        if _deadline_exceeded(t0):
            return False
        return secrets.compare_digest(sig, expected)
    except Exception:
        return False


def _get_server_secret() -> bytes:
    """Get a stable server secret for HMAC signing."""
    from database.crypto import get_server_wrap_key
    return get_server_wrap_key()


# ═══════════════════════════════════════════════════════════════
# FastAPI middleware
# ═══════════════════════════════════════════════════════════════

GATE_ROUTES = {"/gate"}


async def gatekeeper_middleware(request: Request, call_next):
    """
    Gatekeeper middleware — runs BEFORE all other middleware.
    If gate key is not configured, skip entirely.
    If valid gate cookie → continue.
    Otherwise → 404 (API) or gate page (HTML).
    """
    if not GATE_KEY:
        return await call_next(request)

    path = request.url.path

    if path in GATE_ROUTES or path.startswith("/static/"):
        return await call_next(request)

    token = request.cookies.get(GATE_COOKIE, "")
    if token and _verify_gate_token(token, GATE_KEY):
        return await call_next(request)

    return JSONResponse(status_code=404, content={"detail": "Not Found"})


def _serve_gate_page() -> HTMLResponse:
    try:
        path = os.path.join(os.path.dirname(__file__), "gate.html")
        with open(path, "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Elyria</h1><p>Gate key required.</p>", status_code=403)


# ═══════════════════════════════════════════════════════════════
# Gate routes
# ═══════════════════════════════════════════════════════════════

gate_app = APIRouter()


@gate_app.get("/gate")
async def serve_gate_page():
    return _serve_gate_page()


@gate_app.post("/gate")
async def validate_gate(request: Request):
    """Validate the gate key. Hard-capped deadline for timing attack prevention."""
    t0 = time.perf_counter()
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if _deadline_exceeded(t0):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    key = (body.get("key") or "").strip().lower()

    if not KEY_PATTERN.match(key):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if _deadline_exceeded(t0):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if not secrets.compare_digest(key, GATE_KEY):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    if _deadline_exceeded(t0):
        return JSONResponse(status_code=404, content={"detail": "Not Found"})

    token = _sign_gate_token(GATE_KEY)

    from fastapi.responses import JSONResponse as J
    resp = J(content={"gate": True})
    resp.set_cookie(
        GATE_COOKIE, token,
        max_age=GATE_TTL,
        httponly=True,
        samesite="strict",
        secure=False,
    )
    return resp
