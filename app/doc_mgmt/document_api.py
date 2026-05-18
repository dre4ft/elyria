# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

from fastapi import APIRouter, Request, HTTPException, File, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import json 
from yaml import safe_load
from doc_mgmt.openapi import parser as openapi_parser 
from doc_mgmt.arazzo import parser as arazzo_parser 

app = APIRouter(prefix="/api/document")


def _validate_file(file : File):
    if file.filename.endswith(".json") or file.filename.endswith(".yaml") or file.filename.endswith(".yml"):
        if file.content_type == "application/json" or file.content_type == "application/yaml" or file.content_type == "text/yaml" or file.content_type == "application/x-yaml":
            return file.content_type.split("/")[-1][-4:]

    raise  HTTPException(status_code=400,detail="invalid file format !")

class UploadReq(BaseModel):
    target_url: str = "http://localhost:9000"
    team_id: str = ""

@app.post("/openapi")
async def upload(request : Request, target_url: str="http://localhost:9000", team_id: str = "", inputs_values: str = "", openapi_url: str = "", file: UploadFile = File(...), openapi_file: UploadFile = None):
    user_id = request.state.token
    file_type = _validate_file(file)
    try:
        content = file.file.read()
        if file_type == "json":
            content_as_dict = json.loads(content)
        elif file_type == "yaml":
            content_as_dict = safe_load(content)
        else:
            return JSONResponse(status_code=400, content={"detail": "invalid file format"})

        # Route to OpenAPI parser
        if openapi_parser.validate_wrapper(content_as_dict):
            result = openapi_parser.import_to_db(
                parsed=openapi_parser.parse_openapi(content=content_as_dict,server_url=target_url),
                author_user_id=user_id,
            )
            return JSONResponse(status_code=201, content=result)

        # Route to Arazzo parser
        if arazzo_parser.validate_wrapper(content_as_dict):
            # Parse optional inputs_values overrides from query param (JSON string)
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
                    print(f"OpenAPI file parse error: {e}")
            elif openapi_url:
                try:
                    import requests as req
                    r = req.get(openapi_url, timeout=10)
                    if r.status_code == 200:
                        try:
                            openapi_specs[openapi_url] = r.json()
                        except Exception:
                            openapi_specs[openapi_url] = safe_load(r.text)
                except Exception as e:
                    print(f"OpenAPI URL fetch error: {e}")

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
        print(e)
        raise HTTPException(status_code=500, detail="Import failed")


# ── Postman / Bruno import ──────────────────────────────────────────────

@app.post("/postman")
async def upload_postman(request: Request, file: UploadFile = File(...)):
    user_id = request.state.token
    from doc_mgmt.postman.parser import parse_postman
    from database.collection_mgmt import create_folder, create_saved_request

    raw = (await file.read()).decode("utf-8", errors="replace")
    parsed = parse_postman(raw)

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

    raw = (await file.read()).decode("utf-8", errors="replace")
    parsed = parse_bruno(raw, file.filename or "")

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
    
 