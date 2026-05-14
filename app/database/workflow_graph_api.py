"""
Workflow Graph CRUD — persist the visual workflow builder state (nodes + connections).
"""

import json
import re
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

# ── Expression validation ──────────────────────────────────────────────
_FORBIDDEN_EXPR = re.compile(
    r'(?:\b(?:eval|Function|constructor|__proto__|import|require|fetch|XMLHttpRequest'
    r'|document|window|self|top|parent|alert|prompt|confirm|setTimeout|setInterval'
    r'|location|open|close|write|writeln|execScript|execCommand|expression'
    r'|chrome|browser|process|global|globalThis)\b'
    r'|[`$<>]|=>|\\u[0-9a-fA-F]{4})'
)
_EXPR_MAX_LEN = 512


def _validate_expression(expr, field_name="expression"):
    """Reject expressions containing dangerous JS patterns (XSS prevention)."""
    if not expr or not isinstance(expr, str):
        return
    expr_s = expr.strip()
    if len(expr_s) > _EXPR_MAX_LEN:
        raise HTTPException(400, f"'{field_name}' too long (max {_EXPR_MAX_LEN} chars)")
    if _FORBIDDEN_EXPR.search(expr_s):
        raise HTTPException(400, f"'{field_name}' contains forbidden pattern")


def _validate_graph_expressions(graph):
    """Walk all nodes in the graph and validate expression/condition fields."""
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    for node in nodes:
        data = node.get("data", {}) if isinstance(node, dict) else {}
        for field in ("condition", "expression", "expr"):
            val = data.get(field)
            if val and isinstance(val, str):
                _validate_expression(val, f"node.{node.get('type', '?')}.{field}")


from database.auth_utils import get_auth_user, get_auth_user_teams


from core.auth import verify_ownership as _verify_ownership, verify_team_membership as _verify_team_membership


@app.post("")
async def api_save_workflow(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    graph = body.get("graph", {})
    if not name:
        raise HTTPException(400, "name is required")
    if not graph:
        raise HTTPException(400, "graph is required")
    _validate_graph_expressions(graph)
    team_id = body.get("team_id", "")
    user_id = get_auth_user(request)
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
    user_id = get_auth_user(request)
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
    _verify_ownership(wf, get_auth_user(request), get_auth_user_teams(request))
    return wf


@app.put("/{workflow_id}")
async def api_update_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    _verify_ownership(wf, get_auth_user(request), get_auth_user_teams(request))
    body = await request.json()
    graph = body.get("graph", wf["graph"])
    _validate_graph_expressions(graph)
    team_id = body.get("team_id", wf.get("team_id", ""))
    if team_id and team_id != wf.get("team_id", ""):
        _verify_team_membership(team_id, get_auth_user(request))
    update_workflow(
        workflow_id,
        name=body.get("name", wf["name"]),
        graph=graph,
        description=body.get("description", wf.get("description", "")),
        team_id=team_id,
    )
    return {"status": "updated"}


@app.delete("/{workflow_id}")
async def api_delete_workflow(workflow_id: str, request: Request):
    wf = get_workflow(workflow_id)
    _verify_ownership(wf, get_auth_user(request), get_auth_user_teams(request))
    delete_workflow(workflow_id)
    return {"status": "deleted"}


@app.post("/{workflow_id}/run")
async def api_run_workflow(workflow_id: str, request: Request):
    """Execute a workflow server-side and return captured outputs (for Bearer extraction)."""
    wf = get_workflow(workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    _verify_ownership(wf, get_auth_user(request), get_auth_user_teams(request))

    graph = wf.get("graph", {})
    nodes = graph.get("nodes", [])
    connections = graph.get("connections", [])

    # Build lookup maps
    node_map = {n["id"]: n for n in nodes}
    conn_map = {}  # fromId → list of {to, fromPort, toPort}
    for c in connections:
        conn_map.setdefault(c["from"], []).append(c)

    # Find start node
    start_node = next((n for n in nodes if n.get("type") == "start"), None)
    if not start_node:
        raise HTTPException(400, "Workflow has no Start node")

    # Execute nodes sequentially following the graph
    ctx = {}
    executed = set()
    current_id = start_node["id"]

    import requests as req_lib
    from request_manager.request_api import _make_request, _get_proxy_from_request

    while current_id and current_id not in executed:
        node = node_map.get(current_id)
        if not node:
            break
        executed.add(current_id)
        node_type = node.get("type", "")
        node_data = node.get("data", {})

        if node_type == "start":
            pass
        elif node_type == "set_data":
            try:
                vars_data = json.loads(node_data.get("variables", "{}"))
                save_to = node_data.get("saveTo", "")
                if save_to:
                    ctx[save_to] = vars_data
                else:
                    ctx.update(vars_data)
            except Exception:
                pass
        elif node_type == "http_request":
            url = node_data.get("url", "")
            method = node_data.get("method", "GET")
            headers = {}
            try:
                headers = json.loads(node_data.get("headers", "{}"))
            except Exception:
                pass
            body = node_data.get("body")
            json_body = None
            try:
                if body:
                    json_body = json.loads(body)
                    body = None
            except Exception:
                pass
            proxies = _get_proxy_from_request(request)
            try:
                resp = _make_request(
                    method=method, url=url, headers=headers,
                    body=body, _json=json_body, proxies=proxies,
                )
            except Exception as e:
                resp = {"status_code": 0, "url": url, "headers": {}, "body": "", "error": str(e)}
            save_to = node_data.get("saveTo", "response")
            ctx[save_to] = resp
            step_name = node_data.get("label", "") or node.get("id", "")
            if step_name:
                ctx[step_name] = resp

        # Follow the 'out' connection (main path)
        outgoing = conn_map.get(current_id, [])
        next_conn = next(
            (c for c in outgoing if c.get("fromPort", "out") in ("out", "out_true")),
            outgoing[0] if outgoing else None,
        )
        current_id = next_conn["to"] if next_conn else None

    # Extract potential Bearer tokens from outputs
    bearer_candidates = {}
    for key, val in ctx.items():
        if isinstance(val, dict):
            # Check response headers for Authorization / Bearer
            resp_headers = val.get("headers", {})
            for hk, hv in resp_headers.items():
                if hk.lower() == "authorization" and "bearer" in str(hv).lower():
                    bearer_candidates[f"{key}.headers.Authorization"] = str(hv)
            # Check response body for tokens (JSON with token/access_token fields)
            body = val.get("body", "")
            try:
                body_json = json.loads(body) if isinstance(body, str) else body
                if isinstance(body_json, dict):
                    for token_key in ("token", "access_token", "sessionToken", "bearer", "jwt", "id_token"):
                        if token_key in body_json and body_json[token_key]:
                            bearer_candidates[f"{key}.body.{token_key}"] = str(body_json[token_key])
            except Exception:
                pass
        elif isinstance(val, str):
            if val.startswith("eyJ") and "." in val:
                bearer_candidates[key] = val

    return JSONResponse(content={
        "outputs": ctx,
        "bearer_candidates": bearer_candidates,
    })
