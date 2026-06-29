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

import os
import re

# Docker host replacement: only active when ELYRIA_DOCKER_HOST is set.
# When set (e.g. ELYRIA_DOCKER_HOST=host.docker.internal), localhost/127.0.0.1
# in tool URLs/commands are replaced so Ely can reach host services from sandbox.
_DOCKER_HOST = os.getenv("ELYRIA_DOCKER_HOST", "")


def _sanitize_url(url: str) -> str:
    if not _DOCKER_HOST or not url or not isinstance(url, str):
        return url
    return re.sub(
        r'(https?://)(localhost|127\.0\.0\.1|0\.0\.0\.0)([:/?#]|$)',
        r'\1' + _DOCKER_HOST + r'\3',
        url,
        flags=re.IGNORECASE
    )

ACTIONS = {}


def _action(name, description, parameters, optional=None):
    optional = optional or []
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
                        "required": [k for k in parameters.keys() if k not in optional],
                    },
                },
            },
            "handler": handler,
        }
        return handler
    return decorator





def _resolve_folder_id(collection_id: str, user_id: str) -> str | None:
    """Resolve a collection identifier to a folder UUID.

    Accepts: folder UUID (f-xxxxxxxx), simple name, or path like 'Parent/Child'.
    Returns the folder UUID if found, None if collection_id is empty, or the
    original value if it already looks like a UUID.
    """
    if not collection_id or not collection_id.strip():
        return None
    cid = collection_id.strip()
    # Already a folder UUID
    if cid.startswith("f-") and len(cid) >= 10:
        return cid
    # Resolve by name or path
    from database.collection_mgmt import find_folder_by_path
    resolved = find_folder_by_path(cid, user_id)
    if resolved:
        return resolved
    # Fallback: return original value (may be orphaned but won't crash)
    return cid if cid.startswith("f-") else None


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
            url=_sanitize_url(args["url"]),
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
        req_id, resp = handle_raw(user_id=user_id, url=_sanitize_url(args["url"]), request=args["request"], is_done_by_ai=True)
        return {"status": resp.get("status_code", 0), "data": resp, "request_id": req_id}
    except Exception as e:
        return {"error": str(e)[:200]}



@_action("ely_fuzz", "fuzz an HTTP request with a list of payloads and send them, use it instead of sandbox tool",
            {"request": {"type": "object", "properties": {
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
                "url": {"type": "string"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            }},
          "payloads": {"type": "array", "items": {"type": "string"}},
          "fuzzing_type": {"type": "string", "enum": ["sniper"]}})
async def fuzz(args, request):
    from ely.superfuzzer3000 import fuzz_and_send
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    try:
        req = args["request"]
        if isinstance(req, dict) and req.get("url"):
            req["url"] = _sanitize_url(req["url"])
        _log.info(f"User {user_id} is fuzzing request: {req} with payloads: {args['payloads']}")
        fuzzing_type = args.get("fuzzing_type", "sniper")
        responses = fuzz_and_send(req, args["payloads"], fuzzing_type=fuzzing_type)
        return {"status": 200, "data": responses}
    except Exception as e:
        return {"error": str(e)[:200]}

@_action("ely_create_request", "Create an HTTP request. collection_id can be a folder UUID (f-xxxxxxxx), a folder name, or a path like 'Parent/Child'. Omit to create at root.",
         {"method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
          "url":    {"type": "string"},
          "headers":{"type": "string"},
          "body":   {"type": "string"},
          "name":   {"type": "string"},
          "collection_id": {"type": "string", "description": "Folder UUID (f-xxx), name, or path like 'Parent/Child'. Leave empty for root."}},
         optional=["collection_id"])
async def create_request(args, request):
    from database.collection_api import api_create_request, CreateRequestBody
    try:
        hdrs = json.loads(args.get("headers", "{}")) if args.get("headers") else None
    except Exception:
        hdrs = None
    try:
        from core.auth import get_user as get_user_id
        folder_id = _resolve_folder_id(args.get("collection_id", ""), get_user_id(request))
        _request = CreateRequestBody(
            name=args["name"],
            method=args["method"],
            url=args["url"],
            headers=hdrs,
            body=args.get("body", ""),
            folderId=folder_id,
            team_id="",
            isDoneByAI=True)
        exit = api_create_request(_request, request)
        if exit.status_code == 201:
            return {"status": 201, "data": {"message": "Request created successfully"}}
        else:
            body = getattr(exit, 'body', b'') or b''
            return {"error": f"Failed to create request: {body.decode()[:200]}"}
    except Exception as e:
        import traceback
        _log.error(f"create_request failed: {traceback.format_exc()}")
        return {"error": str(e)[:200]}

@_action("ely_request_ctx", "Get the user context dictionary. Returns all keys available for use with {{ctx.xxx}} syntax in request tools.",
         {})
async def get_ctx(args, request):
    from request_manager.request_api import _resolve_request_ctx
    result = _resolve_request_ctx(request)
    if not result:
        return {"error": "User context not found"}
    return {"status": 200, "data": result}



@_action("ely_create_collection", "Create a new collection/folder to organize requests. parent_id can be a folder UUID (f-xxx), name, or path like 'Parent/Child'. Omit for root.",
         {"name": {"type": "string"}, "parent_id": {"type": "string", "description": "Parent folder UUID, name, or path. Leave empty for root."}},
         optional=["parent_id"])
async def create_collection(args, request):
    from database.collection_api import api_create_folder, CreateFolderBody
    try:
        from core.auth import get_user as get_user_id
        parent_id = _resolve_folder_id(args.get("parent_id", ""), get_user_id(request))
        _request = CreateFolderBody(
            name=args["name"],
            parentId=parent_id,
            team_id="",
        )
        exit = api_create_folder(_request, request)
        if exit.status_code == 201:
            return {"status": 201, "data": {"message": "Collection created successfully"}}
        else:
            body = getattr(exit, 'body', b'') or b''
            return {"error": f"Failed to create collection: {body.decode()[:200]}"}
    except Exception as e:
        import traceback
        _log.error(f"create_collection failed: {traceback.format_exc()}")
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
    from greyteam.database import create_report as _create, get_profile, add_finding, update_report
    import threading, json as _json
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    if not user_id:
        return {"error": "User not authenticated"}
    
    profile = get_profile(args["profile_id"])
    if not profile:
        return {"error": "Profile not found"}
    rid = _create(profile_id=args["profile_id"], name="OSINT via Ely")
    def _run():
        from greyteam.osint_scanner import OSINTDomainScanner
        domain = profile.get("target_domain", "")
        categories = profile.get("categories", "[]")
        if isinstance(categories, str):
            try: categories = _json.loads(categories)
            except: categories = []
        try:
            scanner = OSINTDomainScanner(domain=domain, modules=categories)
            findings = scanner.run_all()
            for f in findings:
                add_finding(report_id=rid, title=f.get("title",""), severity=f.get("severity","medium"),
                    category=f.get("category",""), description=f.get("description",""),
                    evidence=f.get("evidence",""), remediation=f.get("remediation",""),
                    cwe_id=f.get("cwe_id",""), source="deterministic", finding_type=f.get("finding_type","osint"))
            update_report(rid, status="completed")
        except Exception:
            update_report(rid, status="failed")
    threading.Thread(target=_run, daemon=True).start()
    return {"status": 200, "data": {"report_id": rid}}


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
        return {"status": 200, "data": {"items": items[:100], "total": len(items)}}
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
        cmd = _sanitize_url(args["command"])
        output = bash.handle(params={"command": cmd, "timeout_ms": 60_000})
        return {"status": 200, "data": {"output": output}}
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_browser_query", "Use a headless browser to interact with web pages, useful for complex interactions and JS-heavy sites",
            {"url": {"type": "string"}, "selector": {"type": "string", "description": "CSS selector for the element to interact with"}})
async def browser_query_tool(args, request):
    from ely.browser import basic_handler
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    try:
        result = await basic_handler(user_id=user_id, url=_sanitize_url(args["url"]), selector=args.get("selector", "body"), action="query")
        return {"status": 200, "data": {"result": result}}
    except Exception as e:
        return {"error": str(e)[:200]}
    
@_action("ely_search_engine", "Search the web for information",
            {"query": {"type": "string"}, })
async def search_engine(args, request):
    from ely.search_engine import search_engine_async
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    try:
        result = await search_engine_async(query=args["query"])
        return {"status": 200, "data": {"result": result}}
    except Exception as e:
        return {"error": str(e)[:200]}
    
@_action("ely_browser_click", "Use a headless browser to interact with web pages, useful for complex interactions and JS-heavy sites",
            {"url": {"type": "string"}, "selector": {"type": "string", "description": "CSS selector for the element to interact with"}})
async def browser_click_tool(args, request):
    from ely.browser import basic_handler
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    try:
        result = await basic_handler(user_id=user_id, url=_sanitize_url(args["url"]), selector=args.get("selector", "body"), action="click")
        return {"status": 200, "data": {"result": result}}
    except Exception as e:
        return {"error": str(e)[:200]}



@_action("ely_list_document", "list documents in the GED (Gestion Electronique de Documents) storage",
            {"team_id": {"type": "string", "description": "Optional team ID to filter documents, empty for personnal doc "},"search": {"type": "string", "description": "Optional search term to filter documents by name or content"},"file_type":{"type": "string", "description": "file type of the document ; markdown, openapi, arazzo, other"}})
async def list_documents_tool(args, request):
    from doc_mgmt.database import list_documents
    from core.auth import get_user, get_user_teams
    user_id = get_user(request)
    user_teams = get_user_teams(request)
    team_id = args.get("team_id", None)
    if team_id and team_id not in user_teams.split(","):
        return{"error" : "Not a member of the specified team"}
    search = args.get("search", None)
    limit = 15
    file_type = args.get("file_type", None)
    return list_documents(user_id,team_id,file_type,search,limit)



@_action("ely_get_document", "get documents in the GED (Gestion Electronique de Documents) storage",
            {"team_id": {"type": "string", "description": "Optional team ID to filter documentsempty for personnal doc" },"doc_id":{"type": "string", "description": "id of the document"}})
async def get_documents_tool(args, request):
    from doc_mgmt.database import get_document,get_document_owner
    from core.auth import get_user, get_user_teams
    _STORAGE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "doc_mgmt", "ged_storage")
    os.makedirs(_STORAGE, exist_ok=True)
    def _storage_path(doc_id):
        return os.path.join(_STORAGE, f"{doc_id}.md")   
    user_id = get_user(request)
    user_teams = get_user_teams(request)
    doc_id = args.get("doc_id", None)
    team_id = args.get("team_id", None)
    doc = get_document(doc_id)
    if not doc:
        return None
    owner_id = get_document_owner(doc_id)
    if owner_id != user_id:
         return "Not the owner of the document"
    if team_id and team_id not in user_teams.split(","):
        return "Not a member of the specified team"
    try:
        with open(_storage_path(doc_id), "r") as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return None

# ═══════════════════════════════════════════════════════════════
# Diary tools — available on all pages
# ═══════════════════════════════════════════════════════════════

@_action("ely_diary_add", "Create a diary entry to record an observation, decision, or important event during the session",
         {"title": {"type": "string", "description": "Short title for the diary entry"},
          "content": {"type": "string", "description": "Markdown content (max 5000 chars)"},
          "page": {"type": "string", "description": "Page context, e.g. 'app', 'pentest'"},
          "tags": {"type": "string", "description": "Optional comma-separated tags"}})
async def diary_add_tool(args, request):
    from ely.diary_database import diary_create
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    did = diary_create(
        user_id=user_id,
        page=args.get("page", ""),
        title=args.get("title", ""),
        content=args.get("content", ""),
        tags=args.get("tags", "").split(",") if args.get("tags") else [],
    )
    return {"status": "ok", "diary_id": did}


@_action("ely_diary_query", "Search diary entries by keyword. Returns matching entries with title, date, and preview.",
         {"query": {"type": "string", "description": "Search keyword(s)"},
          "limit": {"type": "integer", "description": "Max results (default 10)"}})
async def diary_query_tool(args, request):
    from ely.diary_database import diary_search
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    results = diary_search(user_id, query=args.get("query", ""), limit=min(int(args.get("limit", 10)), 50))
    return {"status": "ok", "results": results, "count": len(results)}


@_action("ely_diary_list", "List recent diary entries. Returns entries newest first with title, date, page, and a preview.",
         {"limit": {"type": "integer", "description": "Max entries (default 20)"},
          "page": {"type": "string", "description": "Optional page filter"}})
async def diary_list_tool(args, request):
    from ely.diary_database import diary_list, diary_count
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    items = diary_list(user_id, page=args.get("page") or None, limit=min(int(args.get("limit", 20)), 100))
    total = diary_count(user_id)
    return {"status": "ok", "entries": items, "total": total}


@_action("ely_diary_get", "Get the full content of a specific diary entry by its ID.",
         {"diary_id": {"type": "string", "description": "ID of the diary entry"}})
async def diary_get_tool(args, request):
    from ely.diary_database import diary_get
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    entry = diary_get(args.get("diary_id", ""), user_id)
    if not entry:
        return {"error": "Diary entry not found"}
    return {"status": "ok", "entry": entry}


@_action("ely_diary_delete", "Delete a diary entry by its ID.",
         {"diary_id": {"type": "string", "description": "ID of the diary entry to delete"}})
async def diary_delete_tool(args, request):
    from ely.diary_database import diary_delete
    from core.auth import get_user as get_user_id
    user_id = get_user_id(request)
    ok = diary_delete(args.get("diary_id", ""), user_id)
    return {"status": "ok" if ok else "error"}


# ═══════════════════════════════════════════════════════════════
# Skills management
# ═══════════════════════════════════════════════════════════════

@_action("ely_create_skill", "Create or update a custom agent skill. Skills are markdown files defining agent behavior, methodology, tool usage, and rules.",
         {"skill_id": {"type": "string", "description": "Unique skill ID (e.g. 'my-api-auditor')"},
          "name": {"type": "string", "description": "Display name"},
          "description": {"type": "string", "description": "Short description"},
          "content": {"type": "string", "description": "Skill markdown with sections: Identity, Methodology, Tool Usage, Rules"},
          "category": {"type": "string", "description": "Category: custom, pentest, osint, code-audit, general"}})
async def create_skill_tool(args, request):
    from core.auth import get_user as get_user_id
    from database.skills_api import save_skill
    uid = get_user_id(request)
    sid = args.get("skill_id", "").strip().lower().replace(" ", "-")
    if not sid or not args.get("content", "").strip():
        return {"error": "skill_id and content required"}
    return save_skill(sid, args.get("name", sid), args.get("description", ""),
                      args["content"], args.get("category", "custom"), uid)


@_action("ely_list_skills", "List all available agent skills (built-in and custom).",
         {"category": {"type": "string", "description": "Filter by category (optional)"}})
async def list_skills_tool(args, request):
    from database.skills_api import list_skills
    skills = list_skills()
    cat = args.get("category", "")
    if cat:
        skills = [s for s in skills if s.get("category") == cat]
    return {"skills": skills, "total": len(skills)}


@_action("ely_get_skill", "Get the full content of a specific skill by ID.",
         {"skill_id": {"type": "string", "description": "Skill ID to retrieve"}})
async def get_skill_tool(args, request):
    from database.skills_api import load_skill
    s = load_skill(args.get("skill_id", ""))
    if not s:
        return {"error": f"Skill not found: {args.get('skill_id')}"}
    return s


# ═══════════════════════════════════════════════════════════════
# Purple Team tools
# ═══════════════════════════════════════════════════════════════

@_action("ely_purpleteam_scan", "Start a Purple Team IAST scan on a repository. Combines static analysis (CVE/CWE/bad practices) with dynamic testing and AI-powered code review.",
         {"profile_name": {"type": "string", "description": "Name for this scan profile"},
          "repo_url": {"type": "string", "description": "Git repository URL (GitHub/GitLab/Bitbucket) or local path"},
          "repo_source": {"type": "string", "description": "Repository source: github, gitlab, bitbucket, or local"},
          "repo_branch": {"type": "string", "description": "Git branch to scan (default: main)"},
          "target_endpoint": {"type": "string", "description": "Live API endpoint for dynamic IAST testing (optional)"},
          "scan_depth": {"type": "string", "description": "Scan depth: quick (static only), full (static+AI), iast (static+dynamic)"}})
async def purpleteam_scan_tool(args, request):
    from core.auth import get_user as get_user_id
    from database.auth_utils import get_auth_user_teams
    from purpleteam.database import create_profile, create_scan, add_finding
    from purpleteam.repo_manager import clone_repo, detect_language
    from purpleteam.static_scanner import StaticScanner

    user_id = get_user_id(request)
    team_ids = get_auth_user_teams(request)

    name = args.get("profile_name", "AI-Initiated Scan")
    repo_url = args.get("repo_url", "")
    repo_source = args.get("repo_source", "github")
    repo_branch = args.get("repo_branch", "main")
    target_endpoint = args.get("target_endpoint", "")
    scan_depth = args.get("scan_depth", "full")

    if not repo_url:
        return {"error": "repo_url is required"}

    pid = create_profile(
        name=name, repo_source=repo_source, repo_url=repo_url,
        repo_branch=repo_branch, target_endpoint=target_endpoint,
        user_id=user_id, team_ids=team_ids, scan_depth=scan_depth,
    )
    sid = create_scan(
        profile_id=pid, name=f"AI Scan — {name}",
        repo_source=repo_source, repo_url=repo_url,
        repo_branch=repo_branch, target_endpoint=target_endpoint,
        user_id=user_id, team_ids=team_ids, scan_depth=scan_depth,
    )

    try:
        repo_path = clone_repo(repo_url, user_id, "", "", repo_branch)
        language, framework = detect_language(repo_path)
        static = StaticScanner(repo_path, user_id)
        count = static.run(sid, add_finding)
        return {
            "status": "completed", "scan_id": sid, "profile_id": pid,
            "findings_count": count, "language": language, "framework": framework,
            "message": f"Static scan complete: {count} findings in {language}/{framework} project",
        }
    except Exception as e:
        return {"status": "failed", "scan_id": sid, "profile_id": pid, "error": str(e)}


@_action("ely_purpleteam_get_findings", "Get findings from a Purple Team scan, with optional filters.",
         {"scan_id": {"type": "string", "description": "Scan ID to get findings for"},
          "severity": {"type": "string", "description": "Filter by severity: critical, high, medium, low, info (optional)"},
          "finding_part": {"type": "string", "description": "Filter by part: cves, cwes, practices (optional)"}})
async def purpleteam_get_findings_tool(args, request):
    from purpleteam.database import get_scan, get_scan_findings
    from core.auth import verify_ownership
    from database.auth_utils import get_auth_user, get_auth_user_teams

    scan_id = args.get("scan_id", "")
    if not scan_id:
        return {"error": "scan_id is required"}

    s = get_scan(scan_id)
    if not s:
        return {"error": "Scan not found"}
    if not verify_ownership(request, s.get("user_id"), s.get("team_ids", [])):
        return {"error": "Access denied"}
    findings = get_scan_findings(scan_id)
    severity = args.get("severity", "")
    part = args.get("finding_part", "")

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if part:
        findings = [f for f in findings if f.get("finding_part") == part]

    return {
        "scan_id": scan_id,
        "total": len(findings),
        "findings": [
            {
                "title": f["title"], "severity": f["severity"],
                "category": f.get("category", ""), "file_path": f.get("file_path", ""),
                "cve_id": f.get("cve_id", ""), "cwe_id": f.get("cwe_id", ""),
                "remediation": f.get("remediation", ""),
            }
            for f in findings[:20]
        ],
    }


# ═══════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════

def get_action_definitions(page=None):
    all_defs = [v["definition"] for v in ACTIONS.values()]
    if not page:
        return all_defs
    page_actions = {
        "app":      ["ely_create_request", "ely_create_collection", "ely_get_request_result", "ely_request_ctx", "ely_send_raw_request", "ely_send_request", "ely_list_resources", "ely_bash", "ely_fuzz","ely_browser_query", "ely_browser_click", "ely_search_engine","ely_list_document","ely_get_document"],
        "workflow": ["ely_create_workflow", "ely_list_resources","ely_bash", "ely_fuzz","ely_list_document","ely_get_document"],
        "pentest":  ["ely_run_scan", "ely_get_findings", "ely_list_resources", "ely_bash", "ely_fuzz","ely_browser_query", "ely_browser_click", "ely_search_engine","ely_list_document","ely_get_document"],
        "greyteam": ["ely_osint_scan", "ely_get_findings", "ely_list_resources", "ely_bash","ely_browser_query", "ely_browser_click", "ely_search_engine","ely_list_document","ely_get_document"],
        "blueteam": ["ely_blueteam_analyze", "ely_get_findings", "ely_list_resources", "ely_bash","ely_list_document","ely_get_document"],
        "hub":      ["ely_list_resources", "ely_create_collection"],
        "doc":        ["ely_get_doc", "ely_list_doc_pages", "ely_search_engine"],
        "purpleteam": ["ely_purpleteam_scan", "ely_purpleteam_get_findings", "ely_list_resources", "ely_bash","ely_list_document","ely_get_document"],
    }
    diary_tools = ["ely_diary_add", "ely_diary_query", "ely_diary_list", "ely_diary_get", "ely_diary_delete"]
    skill_tools = ["ely_create_skill", "ely_list_skills", "ely_get_skill"]
    allowed = set(page_actions.get(page, [])) | set(diary_tools) | set(skill_tools)
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