# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""GED API — upload, list, download, delete documents."""

import os
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
import uuid_utils
from doc_mgmt.database import (
    list_documents,
    get_document,
    insert_document,
    delete_document,
    get_document_owner,
    init_document_db)


app = APIRouter(prefix="/api/ged", tags=["ged"])

# Initialize DB on module load
init_document_db()

# Storage root: app/doc_mgmt/ged_storage/
_STORAGE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "doc_mgmt", "ged_storage")
os.makedirs(_STORAGE, exist_ok=True)


def _storage_path(doc_id):
    return os.path.join(_STORAGE, f"{doc_id}.md")


class DocUploadRequest(BaseModel):
    name: str
    content: str = ""
    snippet: str = ""
    file_type: str = "other"
    team_id: str = ""


@app.get("")
async def api_list_documents(request: Request, team_id: str = None,
        file_type: str = None, search: str = None, limit: int = 10):
    """List documents for the authenticated user, optionally filtered."""
    from core.auth import get_user, get_user_teams
    user_id = get_user(request)
    user_teams = get_user_teams(request)
    if team_id and team_id not in user_teams.split(","):
        raise HTTPException(403, "Not a member of the specified team")
    return list_documents(author_user_id=user_id, team_id=team_id,
                          file_type=file_type, search=search, limit=limit)


@app.get("/types")
async def api_list_types():
    """List valid document types."""
    return ["openapi", "arazzo", "markdown", "other"]


@app.get("/{doc_id}")
async def api_get_document(doc_id: str, request: Request):
    """Get document metadata or skill content."""
    # Check if this is the Ely skill or a custom skill
    from database.skills_api import load_skill
    skill = load_skill(doc_id)
    if skill and (doc_id == "ely" or not skill.get("builtin")):
        return {
            "filename": skill["name"],
            "file_type": "skill",
            "content": skill["content"],
        }

    from core.auth import get_user
    user_id = get_user(request)
    owner_id = get_document_owner(doc_id)
    if owner_id != user_id:
        raise HTTPException(403, "Not the owner of the document")
    doc = get_document(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")
    try :
        with open(_storage_path(doc_id), "rb") as f:
            content = f.read()
    except FileNotFoundError:
        raise HTTPException(404, "Document file not found")
    return {"filename": doc["name"], "file_type": doc["file_type"], "content": content.decode("utf-8", errors="replace")}

def read_document_file(doc_id: str, user_id: str):
    """Read document file content."""
    doc = get_document(doc_id)
    if not doc:
        return None
    owner_id = get_document_owner(doc_id)
    if owner_id != user_id:
        raise HTTPException(403, "Not the owner of the document")
    mime = "text/markdown" if doc["file_type"] == "markdown" else "application/octet-stream"
    try:
        with open(_storage_path(doc_id), "rb") as f:
            content = f.read()
        return content, doc["name"], mime
    except FileNotFoundError:
        return None

@app.get("/{doc_id}/download")
async def api_download_document(doc_id: str, request: Request):
    """Download document file."""
    from core.auth import get_user
    user_id = get_user(request)
    result = read_document_file(doc_id, user_id=user_id)
    if not result:
        raise HTTPException(404, "Document not found")
    content, filename, mime = result
    return Response(content=content, media_type=mime,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})





@app.delete("/{doc_id}")
async def api_delete_document(doc_id: str, request: Request):
    """Delete document."""
    from core.auth import get_user
    import os
    user_id = get_user(request)
    owner_id = get_document_owner(doc_id)
    if owner_id != user_id:
        raise HTTPException(403, "Not the owner of the document")
    delete_document(doc_id)
    try:
        os.remove(_storage_path(doc_id))
    except FileNotFoundError:
        raise HTTPException(404, "Document file not found")
    return {"status": "deleted"}




@app.post("/upload")
async def api_upload_document(request: Request, body: DocUploadRequest):
    """Upload a new document."""
    from core.auth import get_user, get_user_teams
    user_id = get_user(request)
    user_teams = get_user_teams(request)
    if body.team_id and body.team_id not in user_teams.split(","):
        raise HTTPException(403, "Not a member of the specified team")
    content = body.content
    if not content:
        raise HTTPException(400, "Empty file")
    doc_name = body.name.strip() or "untitled"
    uid = insert_document(filename=doc_name, file_type=body.file_type, snippet=body.snippet,
                         author_user_id=user_id, team_id=body.team_id)
    with open(_storage_path(uid), "wb") as f:
        f.write(content.encode("utf-8"))
    return {"doc_id": uid, "name": doc_name}
