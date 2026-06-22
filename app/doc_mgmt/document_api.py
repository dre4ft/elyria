# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from fastapi import APIRouter, Request, HTTPException, Depends, File, Form, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json
from yaml import safe_load

from core.logging import get_logger
from doc_mgmt.openapi import parser as openapi_parser
from doc_mgmt.arazzo import parser as arazzo_parser

_log = get_logger("doc_mgmt")

app = APIRouter(prefix="/api/document")


def _validate_file(file : File):
    if file.filename.endswith(".json") or file.filename.endswith(".yaml") or file.filename.endswith(".yml"):
        if file.content_type == "application/json" or file.content_type == "application/yaml" or file.content_type == "text/yaml" or file.content_type == "application/x-yaml":
            return file.content_type.split("/")[-1][-4:]

    raise  HTTPException(status_code=400,detail="invalid file format !")

class UploadReq(BaseModel):
    target_url: str = "http://localhost:9000"
    team_id: str = ""

class OpenapiUploadReq(BaseModel):
    target_url: str = "http://localhost:9000"
    team_id: str = ""
    inputs_values: str = ""
    openapi_url: str = ""

def _parse_openapi_form(
    target_url: str = Form("http://localhost:9000"),
    team_id: str = Form(""),
    inputs_values: str = Form(""),
    openapi_url: str = Form(""),
) -> OpenapiUploadReq:
    return OpenapiUploadReq(target_url=target_url, team_id=team_id, inputs_values=inputs_values, openapi_url=openapi_url)

@app.post("/openapi")
async def upload(request: Request, params: OpenapiUploadReq = Depends(_parse_openapi_form), file: UploadFile = None, openapi_file: UploadFile = None):
    user_id = request.state.token
    target_url = params.target_url
    team_id = params.team_id
    inputs_values = params.inputs_values
    openapi_url = params.openapi_url


    # If no file but a URL is provided, fetch it
    if file is None and openapi_url:
        from core.security import validate_url_or_raise
        validate_url_or_raise(openapi_url)
        import requests as req
        r = req.get(openapi_url, timeout=15)
        if r.status_code != 200:
            return JSONResponse(status_code=400, content={"detail": f"Failed to fetch URL: {r.status_code}"})
        content = r.text
        content_type = r.headers.get('content-type', '')
        is_yaml = 'yaml' in content_type or openapi_url.endswith('.yaml') or openapi_url.endswith('.yml')
        try:
            content_as_dict = json.loads(content) if not is_yaml else safe_load(content)
        except Exception:
            from yaml import safe_load as _sl
            content_as_dict = _sl(content)
    elif file is not None:
        file_type = _validate_file(file)
        content = file.file.read()
        # Save original file to GED
        _save_to_ged(file.filename or "spec", "openapi", content, user_id, f"Imported {file.filename or 'spec'}", file.filename or "")
        if file_type == "json":
            content_as_dict = json.loads(content)
        elif file_type == "yaml":
            content_as_dict = safe_load(content)
        else:
            return JSONResponse(status_code=400, content={"detail": "invalid file format"})
    else:
        return JSONResponse(status_code=400, content={"detail": "No file or URL provided"})

    try:
        # Route to OpenAPI parser
        if openapi_parser.validate_wrapper(content_as_dict):
            result = openapi_parser.import_to_db(
                parsed=openapi_parser.parse_openapi(content=content_as_dict,server_url=target_url),
                author_user_id=user_id,
            )
            return JSONResponse(status_code=201, content=result)

        # Route to Arazzo parser
        if arazzo_parser.validate_wrapper(content_as_dict):
            # Parse optional inputs_values overrides (JSON string)
            inputs_vals = None
            try:
                inputs_vals = json.loads(inputs_values) if inputs_values else None
            except (json.JSONDecodeError, TypeError):
                pass

            # Load OpenAPI specs if provided (file takes priority over URL)
            openapi_specs = {}
            if openapi_file:
                try:
                    ofc = openapi_file.file.read()
                    if openapi_file.filename.endswith(".json"):
                        openapi_specs[openapi_file.filename] = json.loads(ofc)
                    else:
                        openapi_specs[openapi_file.filename] = safe_load(ofc)
                except Exception as e:
                    _log.exception(f"OpenAPI file parse error")
            elif openapi_url:
                try:
                    from core.security import validate_url_or_raise
                    validate_url_or_raise(openapi_url)
                    import requests as req
                    r = req.get(openapi_url, timeout=10)
                    if r.status_code == 200:
                        try:
                            openapi_specs[openapi_url] = r.json()
                        except Exception:
                            openapi_specs[openapi_url] = safe_load(r.text)
                except Exception as e:
                    _log.exception(f"OpenAPI URL fetch error")

            parsed = arazzo_parser.parse_arazzo(
                content_as_dict,
                openapi_specs=openapi_specs if openapi_specs else None,
                target_server=target_url,
            )
            result = arazzo_parser.import_to_db(
                parsed_workflows=parsed,
                author_user_id=user_id,
                team_id=team_id,
                inputs_values=inputs_vals,
            )
            return JSONResponse(status_code=201, content=result)

        return JSONResponse(status_code=400, content={"detail": "Unrecognized format — not OpenAPI or Arazzo"})
    except Exception as e:
        _log.exception(f"document creation error")
        raise HTTPException(status_code=500, detail=f"Import failed: {str(e)[:200]}")


def _save_to_ged(name: str, file_type: str, content: bytes, user_id: str, snippet: str = "", filename: str = ""):
    """Persist imported file to GED (non-blocking)."""
    from doc_mgmt.database import insert_document
    try: 
        insert_document(name=name, file_type=file_type, content=content, author_user_id=user_id, snippet=snippet, filename=filename)
        with open(f"ged_storage/{name}.md", "wb") as f:
            f.write(content)
        
    except Exception:
        pass  # GED storage is best-effort, never block the main import

# ── Postman / Bruno import ──────────────────────────────────────────────

@app.post("/postman")
async def upload_postman(request: Request, file: UploadFile = File(...)):
    user_id = request.state.token
    from doc_mgmt.postman.parser import parse_postman
    from database.collection_mgmt import create_folder, create_saved_request

    raw = await file.read()
    _save_to_ged(file.filename or "postman_collection", "other", raw, user_id, "Postman collection", file.filename or "")
    raw_str = raw.decode("utf-8", errors="replace")
    parsed = parse_postman(raw_str)

    # Create folder tree
    folder_map = {}
    for fld in parsed.get("folders", []):
        fid = create_folder(name=fld["name"], author_user_id=user_id, parent_id=fld.get("parent_id"))
        folder_map[fld["id"]] = fid

    # Create requests
    count = 0
    for req in parsed.get("requests", []):
        parent = folder_map.get(req.get("folder_id"))
        create_saved_request(
            name=req["name"], author_user_id=user_id,
            folder_id=parent, method=req["method"], url=req["url"],
            headers=req.get("headers"), body=req.get("body"),
        )
        count += 1

    return JSONResponse(status_code=201, content={
        "collection_name": parsed.get("collection_name", "Postman Import"),
        "requests_imported": count,
    })


@app.post("/bruno")
async def upload_bruno(request: Request, file: UploadFile = File(...)):
    user_id = request.state.token
    from doc_mgmt.bruno.parser import parse_bruno
    from database.collection_mgmt import create_saved_request

    raw = await file.read()
    _save_to_ged(file.filename or "bruno_collection", "other", raw, user_id, "Bruno collection", file.filename or "")
    raw_str = raw.decode("utf-8", errors="replace")
    parsed = parse_bruno(raw_str, file.filename or "")

    count = 0
    for req in parsed.get("requests", []):
        create_saved_request(
            name=req["name"], author_user_id=user_id,
            folder_id=None, method=req["method"], url=req["url"],
            headers=req.get("headers"), body=req.get("body"),
        )
        count += 1

    return JSONResponse(status_code=201, content={
        "collection_name": parsed.get("collection_name", "Bruno Import"),
        "requests_imported": count,
    })
    
 