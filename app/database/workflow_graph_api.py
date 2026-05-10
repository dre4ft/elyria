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


def _get_user_teams(request: Request):
    try:
        from database.user_mgmt import get_user_teams
        return get_user_teams(_get_user(request)) or ""
    except Exception:
        return ""


def _verify_ownership(workflow, user_id, user_teams=""):
    """Check if user owns the workflow or is in the owning team."""
    if not workflow:
        raise HTTPException(404, "Workflow not found")
    if workflow.get("user_id") == user_id or not workflow.get("user_id"):
        return
    team_id = workflow.get("team_id", "")
    if team_id and user_teams:
        if team_id in user_teams.split(","):
            return
    raise HTTPException(403, "Access denied")


def _verify_team_membership(team_id, user_id):
    """Raise 403 if user is not a member of the given team."""
    if not team_id:
        return
    try:
        import sqlite3
        conn = sqlite3.connect("database.db")
        row = conn.execute(
            "SELECT 1 FROM team_users WHERE team_id=? AND user_id=?",
            (team_id, user_id),
        ).fetchone()
        conn.close()
        if not row:
            raise HTTPException(403, "You are not a member of this team")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(403, "Team membership check failed")


@app.post("")
async def api_save_workflow(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    graph = body.get("graph", {})
    if not name:
        raise HTTPException(400, "name is required")
    if not graph:
        raise HTTPException(400, "graph is required")
    team_id = body.get("team_id", "")
    user_id = _get_user(request)
    if team_id:
        _verify_team_membership(team_id, user_id)
    wf_id = save_workflow(
        name=name,
        graph=graph,
        user_id=user_id,
        description=body.get("description", ""),
        team_id=team_id,
    )
    return {"workflow_id": wf_id}


@app.get("")
async def api_list_workflows(request: Request, team_id: str = ""):
    user_id = _get_user(request)
    if team_id == "__personal__":
        wfs = list_workflows(user_id=user_id)
    elif team_id:
        _verify_team_membership(team_id, user_id)
        wfs = list_workflows(team_id=team_id)
    else:
        wfs = list_workflows(user_id=user_id, team_id="__followed__")
    return wfs


@app.get("/{workflow_id}")
async def api_get_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    _verify_ownership(wf, _get_user(request), _get_user_teams(request))
    return wf


@app.put("/{workflow_id}")
async def api_update_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    _verify_ownership(wf, _get_user(request), _get_user_teams(request))
    body = await request.json()
    team_id = body.get("team_id", wf.get("team_id", ""))
    if team_id and team_id != wf.get("team_id", ""):
        _verify_team_membership(team_id, _get_user(request))
    update_workflow(
        workflow_id,
        name=body.get("name", wf["name"]),
        graph=body.get("graph", wf["graph"]),
        description=body.get("description", wf.get("description", "")),
        team_id=team_id,
    )
    return {"status": "updated"}


@app.delete("/{workflow_id}")
async def api_delete_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    _verify_ownership(wf, _get_user(request), _get_user_teams(request))
    delete_workflow(workflow_id)
    return {"status": "deleted"}
