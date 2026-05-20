# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from .request_mgmt import get_requests_by_id,get_requests_by_userid
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

app = APIRouter(prefix="/api")


from database.auth_utils import get_auth_user


@app.get("/requests/byId/{request_id}")
def get_req_by_id(request_id: str, request: Request):
    result = get_requests_by_id(request_uuid=request_id)
    if not result:
        raise HTTPException(404, "Request not found")
    if result.get("author_user_id") != get_auth_user(request):
        raise HTTPException(403, "Access denied")
    return JSONResponse(result)


@app.get("/requests/byUserId/{user_id}")
def get_req_by_userid(user_id: str, limit: int = 10, page: int = 1, request: Request = None):
    if not request or get_auth_user(request) != user_id:
        raise HTTPException(403, "Access denied")
    offset = (page - 1) * limit
    result = get_requests_by_userid(user_id, limit, offset)
    return JSONResponse(result)
