# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""User context REST API — GET/PUT persistent ctx dict for template interpolation."""

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .ctx_mgmt import get_ctx, put_ctx
from database.auth_utils import get_auth_user

app = APIRouter(prefix="/api/ctx")


class CtxBody(BaseModel):
    ctx: dict


@app.get("")
def get_user_ctx(request: Request):
    """Return the user's full context object."""
    user_id = get_auth_user(request)
    ctx = get_ctx(user_id)
    return JSONResponse(ctx)


@app.put("")
def put_user_ctx(body: CtxBody, request: Request):
    """Replace the user's context with the supplied object."""
    user_id = get_auth_user(request)
    ok = put_ctx(user_id, body.ctx)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to save context")
    return JSONResponse({"ok": True})
