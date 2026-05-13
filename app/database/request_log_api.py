from .request_mgmt import get_requests_by_id,get_requests_by_userid
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

app = APIRouter(prefix="/api")


def _get_user(r: Request):
    token = getattr(r.state, "token", None)
    if not token or token == "anonymous":
        raise HTTPException(401, "Authentication required")
    return token


@app.get("/requests/byId/{request_id}")
def get_req_by_id(request_id: str, request: Request):
    result = get_requests_by_id(request_uuid=request_id)
    if not result:
        raise HTTPException(404, "Request not found")
    if result.get("author_user_id") != _get_user(request):
        raise HTTPException(403, "Access denied")
    return JSONResponse(result)


@app.get("/requests/byUserId/{user_id}")
def get_req_by_userid(user_id: str, limit: int = 10, page: int = 1, request: Request = None):
    if not request or _get_user(request) != user_id:
        raise HTTPException(403, "Access denied")
    offset = (page - 1) * limit
    result = get_requests_by_userid(user_id, limit, offset)
    return JSONResponse(result)
