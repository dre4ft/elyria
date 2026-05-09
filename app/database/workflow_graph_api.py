"""
Workflow Graph CRUD — persist the visual workflow builder state (nodes + connections).
"""

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse

from database.workflow_graph_mgmt import (
    init_db,
    save_workflow,
    list_workflows,
    get_workflow,
    update_workflow,
    delete_workflow,
)

app = APIRouter(prefix="/api/workflows", tags=["workflows"])

init_db()


def _get_user(request: Request):
    return getattr(request.state, "token", "anonymous")


@app.post("")
async def api_save_workflow(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    graph = body.get("graph", {})
    if not name:
        raise HTTPException(400, "name is required")
    if not graph:
        raise HTTPException(400, "graph is required")

    wf_id = save_workflow(
        name=name,
        graph=graph,
        user_id=_get_user(request),
        description=body.get("description", ""),
    )
    return {"workflow_id": wf_id}


@app.get("")
async def api_list_workflows(request: Request, team_id: str = ""):
    if team_id == "__personal__":
        wfs = list_workflows(user_id=_get_user(request))
    elif team_id:
        wfs = list_workflows(team_id=team_id)
    else:
        wfs = list_workflows(user_id=_get_user(request), team_id="__followed__")
    return wfs
    return wfs


@app.get("/{workflow_id}")
async def api_get_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    return wf


@app.put("/{workflow_id}")
async def api_update_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    body = await request.json()
    update_workflow(
        workflow_id,
        name=body.get("name", wf["name"]),
        graph=body.get("graph", wf["graph"]),
        description=body.get("description", wf.get("description", "")),
    )
    return {"status": "updated"}


@app.delete("/{workflow_id}")
async def api_delete_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    delete_workflow(workflow_id)
    return {"status": "deleted"}
