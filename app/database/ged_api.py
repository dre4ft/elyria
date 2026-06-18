# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""GED API — upload, list, download, delete documents."""

from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from database.auth_utils import get_auth_user, get_auth_user_teams
from database.ged_mgmt import (
    create_document, list_documents, get_document, update_document,
    delete_document, read_document_file, VALID_TYPES,
)

app = APIRouter(prefix="/api/ged", tags=["ged"])


class DocUpdateRequest(BaseModel):
    name: str = None
    snippet: str = None
    team_id: str = None
    file_type: str = None


def _parse_upload_form(
    name: str = Form(...),
    snippet: str = Form(""),
    file_type: str = Form("other"),
    team_id: str = Form(""),
) -> dict:
    return {"name": name, "snippet": snippet, "file_type": file_type, "team_id": team_id}


@app.get("")
async def api_list_documents(request: Request, file_type: str = "", search: str = "",
                              team_id: str = "", limit: int = 50, offset: int = 0):
    """List documents scoped to the authenticated user."""
    uid = get_auth_user(request)
    docs = list_documents(user_id=uid, team_id=team_id, file_type=file_type,
                          search=search, limit=limit, offset=offset)
    # Strip file_path from list responses
    for d in docs:
        d.pop("file_path", None)
    return docs


@app.get("/types")
async def api_list_types():
    """List valid document types."""
    return list(VALID_TYPES)


@app.get("/{doc_id}")
async def api_get_document(doc_id: str, request: Request):
    """Get document metadata."""
    uid = get_auth_user(request)
    doc = get_document(doc_id, user_id=uid)
    if not doc:
        raise HTTPException(404, "Document not found")
    doc.pop("file_path", None)
    return doc


@app.get("/{doc_id}/download")
async def api_download_document(doc_id: str, request: Request):
    """Download document file."""
    uid = get_auth_user(request)
    result = read_document_file(doc_id, user_id=uid)
    if not result:
        raise HTTPException(404, "Document not found")
    content, filename, mime = result
    return Response(content=content, media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.put("/{doc_id}")
async def api_update_document(doc_id: str, body: DocUpdateRequest, request: Request):
    """Update document metadata."""
    uid = get_auth_user(request)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not update_document(doc_id, uid, **updates):
        raise HTTPException(404, "Document not found")
    return {"status": "updated"}


@app.delete("/{doc_id}")
async def api_delete_document(doc_id: str, request: Request):
    """Delete document."""
    uid = get_auth_user(request)
    if not delete_document(doc_id, uid):
        raise HTTPException(404, "Document not found")
    return {"status": "deleted"}


@app.post("/upload")
async def api_upload_document(
    request: Request,
    file: UploadFile = File(...),
    name: str = Form(""),
    snippet: str = Form(""),
    file_type: str = Form("other"),
    team_id: str = Form(""),
):
    """Upload a new document."""
    uid = get_auth_user(request)
    content = await file.read()
    if not content:
        raise HTTPException(400, "Empty file")
    doc_name = name.strip() or (file.filename or "untitled")
    if file_type not in VALID_TYPES:
        file_type = "other"
    doc_id = create_document(
        name=doc_name,
        file_type=file_type,
        user_id=uid,
        file_content=content,
        snippet=snippet.strip(),
        team_id=team_id,
        original_filename=file.filename or "",
    )
    return {"doc_id": doc_id, "name": doc_name, "file_type": file_type}
