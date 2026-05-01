from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from .collection_mgmt import (
    create_folder, delete_folder, get_collection_tree,
    create_saved_request, update_saved_request, delete_saved_request
)

app = APIRouter(prefix="/api/collections")


def get_user_token(request: Request) -> str:
    raw_token = getattr(request.state, "token", None)
    token = raw_token["sub"]
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")
    return token


# ═══════════════════════════════════════════════
# DTOs
# ═══════════════════════════════════════════════

class CreateFolderBody(BaseModel):
    name: str
    parentId: str = None


class CreateRequestBody(BaseModel):
    name: str
    method: str = "GET"
    url: str = ""
    folderId: str = None
    headers: dict = None
    body: str = None
    isDoneByAI: bool = False


class UpdateRequestBody(BaseModel):
    name: str = None
    method: str = None
    url: str = None
    folderId: str = None
    headers: dict = None
    body: str = None


# ═══════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════

@app.get("")
def list_collections(request: Request):
    token = get_user_token(request)
    tree = get_collection_tree(author_user_id=token)
    return JSONResponse(tree)


@app.post("/folder")
def api_create_folder(body: CreateFolderBody, request: Request):
    token = get_user_token(request)
    folder_id = create_folder(
        name=body.name,
        author_user_id=token,
        parent_id=body.parentId
    )
    if folder_id:
        return JSONResponse({"folder_id": folder_id, "name": body.name}, status_code=201)
    raise HTTPException(status_code=500, detail="Failed to create folder")


@app.delete("/folder/{folder_id}")
def api_delete_folder(folder_id: str, request: Request):
    token = get_user_token(request)
    ok = delete_folder(folder_id, author_user_id=token)
    if ok:
        return JSONResponse({"deleted": True})
    raise HTTPException(status_code=500, detail="Failed to delete folder")


@app.post("/request")
def api_create_request(body: CreateRequestBody, request: Request):
    token = get_user_token(request)
    saved_id = create_saved_request(
        name=body.name,
        author_user_id=token,
        folder_id=body.folderId,
        method=body.method,
        url=body.url,
        headers=body.headers,
        body=body.body,
        is_done_by_ai=body.isDoneByAI
    )
    if saved_id:
        return JSONResponse({"saved_request_id": saved_id, "name": body.name}, status_code=201)
    raise HTTPException(status_code=500, detail="Failed to create saved request")


@app.put("/request/{saved_request_id}")
def api_update_request(saved_request_id: str, body: UpdateRequestBody, request: Request):
    token = get_user_token(request)
    update_data = {k: v for k, v in body.model_dump().items() if v is not None}
    ok = update_saved_request(saved_request_id, author_user_id=token, **update_data)
    if ok:
        return JSONResponse({"updated": True})
    raise HTTPException(status_code=500, detail="Failed to update saved request")


@app.delete("/request/{saved_request_id}")
def api_delete_request(saved_request_id: str, request: Request):
    token = get_user_token(request)
    ok = delete_saved_request(saved_request_id, author_user_id=token)
    if ok:
        return JSONResponse({"deleted": True})
    raise HTTPException(status_code=500, detail="Failed to delete saved request")
