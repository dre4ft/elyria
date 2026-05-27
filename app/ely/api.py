# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Ely — FastAPI routes.

Endpoints:
  POST /api/ely/chat     — send a message, get streaming SSE response
  GET  /api/ely/context  — get page context snapshot (called by frontend)
"""

import asyncio
import json
import time
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

from core.logging import get_logger
from core.auth import get_user as get_user_id

_log = get_logger("ely.api")

app = APIRouter(prefix="/api/ely", tags=["ely"])





class ChatMessage(BaseModel):
    page: str = "app"
    message: str = ""
    history: list = []



# ═══════════════════════════════════════════════════════════════
# Chat endpoint (SSE streaming)
# ═══════════════════════════════════════════════════════════════

@app.post("/chat")
async def ely_chat(request: ChatMessage,_request: Request):
    """Send a message to Ely. Returns JSON with reply + actions."""


    page = request.page
    message = request.message
    history = request.history

    if not message:
        return JSONResponse(status_code=400, content={"detail": "Message is required"})

    user_id = get_user_id(_request)

    _log.info(f"Ely chat: user={user_id} page={page} msg_len={len(message)}")

    messages = history + [{"role": "user", "content": message}]
    if len(messages) > 20:
        messages = messages[-20:]

    from ely.agent import chat as ely_chat_fn
    result = await ely_chat_fn(page, messages, _request, slot=getattr(request, 'slot', 'flash'))
    return JSONResponse(content=result)


# ═══════════════════════════════════════════════════════════════
# Context endpoint
# ═══════════════════════════════════════════════════════════════

@app.get("/context")
async def ely_context(request: Request, page: str = "app"):
    """Return a context snapshot for the given page."""
    snapshot = {"page": page}

    try:
        if page == "pentest":
            from redteam.database import list_reports
            reports = list_reports(user_id=get_user_id(request))
            if reports:
                last = reports[0]
                snapshot["active_campaign"] = {
                    "id": last.get("campaign_id") or last.get("report_id", ""),
                    "name": last.get("name", ""),
                    "status": last.get("status", ""),
                    "target": last.get("target_domain", "") or last.get("target_path", ""),
                }

        elif page == "greyteam":
            from greyteam.database import list_reports
            reports = list_reports(user_id=get_user_id(request))
            if reports:
                last = reports[0]
                snapshot["active_report"] = {
                    "id": last.get("report_id", ""),
                    "target": last.get("target_domain", ""),
                    "status": last.get("status", ""),
                }

        elif page == "blueteam":
            from blueteam.database import list_reports
            reports = list_reports(user_id=get_user_id(request))
            if reports:
                last = reports[0]
                snapshot["active_report"] = {
                    "id": last.get("report_id", ""),
                    "target": last.get("target_path", ""),
                    "status": last.get("status", ""),
                }
    except Exception as e:
        _log.warning(f"Context collection failed for page={page}: {e}")

    return snapshot


# ═══════════════════════════════════════════════════════════════
# Audit & Preferences endpoints
# ═══════════════════════════════════════════════════════════════

@app.get("/audit")
async def ely_audit(request: Request, page: str = "", action: str = "", limit: int = 50, offset: int = 0):
    """Get Ely audit logs for the current user."""
    from ely.database import get_audit_logs
    user_id = get_user_id(request)
    logs = get_audit_logs(user_id, page=page or None, action=action or None, limit=min(limit, 200), offset=offset)
    return {"logs": logs, "total": len(logs)}


@app.get("/stats")
async def ely_stats(request: Request):
    """Get Ely usage stats for the current user."""
    from ely.database import get_audit_stats
    user_id = get_user_id(request)
    return get_audit_stats(user_id)


@app.get("/preferences")
async def ely_get_preferences(request: Request):
    """Get Ely preferences for the current user."""
    from ely.database import get_preferences
    user_id = get_user_id(request)
    return get_preferences(user_id)


@app.put("/preferences")
async def ely_save_preferences(request: Request):
    """Save Ely preferences for the current user."""
    from ely.database import save_preferences
    user_id = get_user_id(request)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"detail": "Invalid JSON"})
    prefs = save_preferences(user_id, **body)
    return prefs
