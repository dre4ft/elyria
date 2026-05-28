# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Ely — Action definitions. All calls are direct Python function
invocations (no HTTP loopback → no deadlock, no connection reset).
"""

import json
import threading
from core.logging import get_logger

_log = get_logger("ely.actions")

ACTIONS = {}


def _action(name, description, parameters):
    def decorator(handler):
        ACTIONS[name] = {
            "definition": {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": {
                        "type": "object",
                        "properties": parameters,
                        "required": list(parameters.keys()),
                    },
                },
            },
            "handler": handler,
        }
        return handler
    return decorator





# ═══════════════════════════════════════════════════════════════
# Action handlers — direct Python calls, no HTTP
# ═══════════════════════════════════════════════════════════════

@_action("ely_send_request", "send an HTTP request",
         {"method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
          "url":    {"type": "string"},
          "headers":{"type": "string"},
          "body":   {"type": "string"}})
async def send_request(args, request):
    from request_manager.request_api import handle_request
    from core.auth import get_user as get_user_id
    try:
        hdrs = json.loads(args.get("headers", "{}")) if args.get("headers") else None
    except Exception:
        hdrs = None
    try:
        user_id = get_user_id(request)
        uid, resp = handle_request(
            user_id=user_id,
            url=args["url"],
            method=args["method"],
            headers=hdrs,
            body=args.get("body", ""),
            is_done_by_ai=True,
        )
        return {"status": resp.get("status_code", 0), "data": resp, "request_id": uid}
    except Exception as e:
        return {"error": str(e)[:200]}

@_action("ely_get_request_log", "get the log of a previously sent HTTP request",
         {"request_id": {"type": "string"}})
async def get_request_log(args, request):
    from database.request_log_api import get_req_by_id
    try:
        req_id = args["request_id"]
        req = get_req_by_id(req_id, request)
        if not req:
            return {"error": "Request not found"}
        return {"status": 200, "data": req} 
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_send_raw_request", "send a raw HTTP request",
         {"url": {"type": "string"},
          "request": {"type": "string"}})
async def send_raw_request(args, request):
    from request_manager.request_api import handle_raw
    from core.auth import get_user as get_user_id
    try:
        user_id = get_user_id(request)
        req_id, resp = handle_raw(user_id=user_id, url=args["url"], request=args["request"], is_done_by_ai=True)
        return {"status": resp.get("status_code", 0), "data": resp, "request_id": req_id}
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_create_request", "Create an HTTP request",
         {"method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
          "url":    {"type": "string"},
          "headers":{"type": "string"},
          "body":   {"type": "string"},
          "name":   {"type": "string"},
          "collection_id": {"type": "string"}})
async def create_request(args, request):
    from database.collection_api import api_create_request, CreateRequestBody
    try:
        hdrs = json.loads(args.get("headers", "{}")) if args.get("headers") else None
    except Exception:
        hdrs = None
    try:
        _request = CreateRequestBody(
            name=args["name"],
            method=args["method"],
            url=args["url"],
            headers=hdrs,
            body=args.get("body", ""),
            folderId=args.get("collection_id"),
            team_id="",
            isDoneByAI=True)
        exit = api_create_request(_request, request)
        if exit.status_code == 201:
            return {"status": 201, "data": {"message": "Request created successfully"}}
        else:
            return {"error": f"Failed to create request: {exit.content.decode()[:200]}"}

    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_create_collection", "Create a new collection/folder to organize requests",
         {"name": {"type": "string"}, "parent_id": {"type": "string"}})
async def create_collection(args, request):
    from database.collection_api import api_create_folder, CreateFolderBody
    try:
        _request = CreateFolderBody(
            name=args["name"],
            parentId=args.get("parent_id"),
            team_id="",
        )
        exit = api_create_folder(_request, request)
        if exit.status_code == 201:
            return {"status": 201, "data": {"message": "Collection created successfully"}}
        else:
            return {"error": f"Failed to create collection: {exit.content.decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_run_scan", "Launch a Red Team pentest scan",
         {"profile_id": {"type": "string"}, "name": {"type": "string"}})
async def run_scan(args,  request):
    from redteam.campaign_api import api_start_scan
    profile = args["profile_id"]
    if not profile:
        return {"error": "Profile not found"}
    
    try:
        import asyncio
        asyncio.ensure_future(api_start_scan(profile_id=profile, request=request))
        return {"status": 200, "data": "Scan started successfully you can check the report page for live updates."}
    except Exception as e :
        return {"error": str(e)[:200]}


    '''try:
        result = await api_start_scan(profile_id=profile, request=request)
        return {"status": 200, "data": result}
    except Exception as e:
        return {"error": str(e)[:200]}'''
    
    


@_action("ely_osint_scan", "Launch a Grey Team OSINT scan on a domain",
         {"profile_id": {"type": "string"}})
async def osint_scan(args,request):
    from greyteam.api import api_start_scan
    profile = args["profile_id"]
    if not profile:
        return {"error": "Profile not found"}
    
    try:
        import asyncio
        asyncio.ensure_future(api_start_scan(profile_id=profile, request=request))
        return {"status": 200, "data": "Scan started successfully you can check the report page for live updates."}
    except Exception as e :
        return {"error": str(e)[:200]}
    
    """ try:
        exit = api_start_scan(profile_id=profile, request=request)
        



        if exit.status_code == 200:
            data = json.loads(exit.content.decode())
            return {"status": 200, "data": {"report_id": data.get("report_id")}}
        else:
            return {"error": f"Failed to start OSINT scan: {exit.content.decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)[:200]}"""


@_action("ely_blueteam_analyze", "Launch a Blue Team security analysis on an API spec",
         {"profile_id": {"type": "string"}})
async def blueteam_analyze(args, request):
    from blueteam.api import api_start_analysis
    profile = args["profile_id"]
    if not profile:
        return {"error": "Profile not found"}
    try:
        import asyncio
        asyncio.ensure_future(api_start_scan(profile_id=profile, request=request))
        return {"status": 200, "data": "Scan started successfully you can check the report page for live updates."}
    except Exception as e :
        return {"error": str(e)[:200]}
    try:
        exit = api_start_analysis(profile_id=profile, request=request)
        if exit.status_code == 200:
            data = json.loads(exit.content.decode())
            return {"status": 200, "data": {"report_id": data.get("report_id")}}
        else:
            return {"error": f"Failed to start analysis: {exit.content.decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_create_workflow", "Create a new workflow",
         {"name": {"type": "string"}, "blocks": {"type": "string"}})
async def create_workflow(args, user_id, request):
    from database.workflow_graph_api import api_save_workflow, WorkflowCreateRequest
    try:
        blocks = json.loads(args["blocks"])
    except Exception:
        return {"error": "Invalid blocks format, must be a JSON string"}
    try:
        _request = WorkflowCreateRequest(
            name=args["name"],
            graph=blocks,
            description="Ely-created workflow",
            team_id="",
        )
        exit = api_save_workflow(_request, request)
        if exit.status_code == 200:
            data = json.loads(exit.content.decode())
            return {"status": 200, "data": {"workflow_id": data.get("workflow_id")}}
        else:
            return {"error": f"Failed to create workflow: {exit.content.decode()[:200]}"}
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_get_findings", "Get findings from a report",
         {"id": {"type": "string"},
          "team": {"type": "string", "enum": ["redteam", "greyteam", "blueteam"]}})
async def get_findings(args, request):
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    team = args["team"]
    if team == "redteam":
        from redteam.database import get_finding_detail_log , get_last_campaign_by_user
        last = get_last_campaign_by_user(user_id)
        if not last:
            return {"error": "No campaign found for user"}
        findings = get_finding_detail_log(last.get("campaign_id", ""),finding_id=args["id"])
    #TODO PAs que le last var sur l"id avec ownership
    elif team == "greyteam":
        from greyteam.database import get_last_report_by_user
        findings = get_last_report_by_user(user_id)
    elif team == "blueteam":
        from blueteam.database import get_last_report_by_user 
        findings = get_last_report_by_user(user_id)
    else:
        return {"error": "Invalid team specified"}
    return {"status": 200, "data": {"findings": findings, "total": len(findings)}}


@_action("ely_list_resources", "List resources (profiles, collections, workflows)",
         {"resource": {"type": "string", "enum": ["collections", "redteam_profiles",
                          "greyteam_profiles", "blueteam_profiles", "workflows"]}})
async def list_resources(args,request):
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    r = args["resource"]
    try:
        if r == "collections":
            from database.collection_mgmt import get_collection_tree as L
            items = L(user_id)
        elif r == "redteam_profiles":
            from redteam.database import list_profiles as L
            items = L(user_id=user_id)
        elif r == "greyteam_profiles":
            from greyteam.database import list_profiles as L
            items = L(user_id=user_id)
        elif r == "blueteam_profiles":
            from blueteam.database import list_profiles as L
            items = L(user_id=user_id)
        else:
            from database.workflow_graph_mgmt import list_workflows as L
            items = L(user_id=user_id)
        return {"status": 200, "data": {"items": items[:20], "total": len(items)}}
    except Exception as e:
        return {"error": str(e)[:200]}



@_action("ely_get_doc", "look up a documentation snippet from the Ely knowledge base",
         {"page": {"type": "string"}})
async def get_doc(args, request):
    doc = "../doc/guide-utilisateur-en.md"
    try:
        with open(doc, "r") as f:
            content = f.read()
        start = content.find(f"## {args['page']}")
        if start == -1:
            return {"error": "Page not found"}
        end = content.find("\n##", start + 1)
        if end == -1:
            end = len(content)
        content = content[start:end].strip()
        return {"status": 200, "data": {"content": content}}
    except Exception as e:
        return {"error": str(e)[:200]}
    

@_action("ely_list_doc_pages", "List available documentation pages",
         {})
async def list_doc_pages(args, request):
    doc = "../doc/guide-utilisateur-en.md"
    try:
        with open(doc, "r") as f:
            content = f.read()
        pages = []
        idx = 0
        while True:
            idx = content.find("\n## ", idx)
            if idx == -1:
                break
            end_idx = content.find("\n", idx + 4)
            if end_idx == -1:
                end_idx = len(content)
            page_title = content[idx + 4:end_idx].strip()
            pages.append(page_title)
            idx = end_idx
        return {"status": 200, "data": {"pages": pages}}
    except Exception as e:
        return {"error": str(e)[:200]}



@_action("ely_bash", "Execute a bash command in an isolated sandbox environment",
            {"command": {"type": "string"}})
async def bash_tool(args, request):
    from ely.sandbox_spawn import get_bash_tool
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    bash = get_bash_tool(user_id)
    if not bash:
        return {"error": "Failed to initialize sandbox"}
    try:
        output = bash.handle(params={"command": args["command"], "timeout_ms": 60_000})
        return {"status": 200, "data": {"output": output}}
    except Exception as e:
        return {"error": str(e)[:200]}



# ═══════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════

def get_action_definitions(page=None):
    all_defs = [v["definition"] for v in ACTIONS.values()]
    if not page:
        return all_defs
    page_actions = {
        "app":      ["ely_create_request", "ely_create_collection", "ely_get_request_result", "ely_send_raw_request", "ely_send_request", "ely_list_resources", "ely_bash"],
        "workflow": ["ely_create_workflow", "ely_list_resources","ely_bash"],
        "pentest":  ["ely_run_scan", "ely_get_findings", "ely_list_resources", "ely_bash"],
        "greyteam": ["ely_osint_scan", "ely_get_findings", "ely_list_resources", "ely_bash"],
        "blueteam": ["ely_blueteam_analyze", "ely_get_findings", "ely_list_resources", "ely_bash"],
        "hub":      ["ely_list_resources", "ely_create_collection"],
        "doc":      ["ely_get_doc", "ely_list_doc_pages"],
    }
    allowed = set(page_actions.get(page, []))
    return [d for d in all_defs if d.get("function", {}).get("name") in allowed or page is None]


async def execute_action(name, args,request, page=None):
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    if name not in ACTIONS:
        return {"error": f"Unknown action: {name}"}
    handler = ACTIONS[name]["handler"]
    try:
        _log.info(f"Action '{name}' args={json.dumps(args, default=str)[:200]}")
        result = await handler(args, request)
        if user_id:
            from ely.database import log_action
            log_action(user_id, page or "", name, args, result,
                       "ok" if "error" not in result else "error", 0)
        return result
    except Exception as e:
        _log.error(f"Action '{name}' failed: {e}")
        if user_id:
            from ely.database import log_action
            log_action(user_id, page or "", name, args, {"error": str(e)[:300]}, "error", 0)
        return {"error": str(e)[:300]}


if __name__ == "__main__":
    # Quick test
    import asyncio
    result = asyncio.run(execute_action("ely_list_doc_pages", {}, None))
    print(result)