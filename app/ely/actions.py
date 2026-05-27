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


def _extract_user(token):
    import base64
    try:
        parts = token.split(".")
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("sub", "anon")
    except Exception:
        return "anon"


# ═══════════════════════════════════════════════════════════════
# Action handlers — direct Python calls, no HTTP
# ═══════════════════════════════════════════════════════════════

@_action("ely_create_request", "Create and send an HTTP request",
         {"method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
          "url":    {"type": "string"},
          "headers":{"type": "string"},
          "body":   {"type": "string"},
          "name":   {"type": "string"},
          "collection_id": {"type": "string"}})
async def create_request(args, user_id):
    from request_manager.request_api import handle_request
    try:
        hdrs = json.loads(args.get("headers", "{}")) if args.get("headers") else None
    except Exception:
        hdrs = None
    try:
        uid, resp = handle_request(
            user_id=user_id,
            url=args["url"],
            method=args["method"],
            headers=hdrs,
            body=args.get("body", ""),
        )
        return {"status": resp.get("status_code", 0), "data": resp}
    except Exception as e:
        return {"error": str(e)[:200]}


@_action("ely_create_collection", "Create a new collection/folder to organize requests",
         {"name": {"type": "string"}, "parent_id": {"type": "string"}})
async def create_collection(args, user_id):
    from database.collection_mgmt import create_folder
    fid = create_folder(
        name=args["name"],
        author_user_id=user_id,
        parent_id=args.get("parent_id") or None,
        team_id="",
    )
    return {"status": 200, "data": {"folder_id": fid}}


@_action("ely_run_scan", "Launch a Red Team pentest scan",
         {"profile_id": {"type": "string"}})
async def run_scan(args, user_id, token=None):
    import requests, asyncio
    from database.app_config import get
    base = f"http://{get('app.host', '127.0.0.1')}:{get('app.port', '8000')}"
    def _post():
        r = requests.post(f"{base}/api/pentest/reports",
            json={"profile_id": args["profile_id"]},
            headers={"Authorization": f"Bearer {token}"} if token else {},
            timeout=30)
        try: return {"status": r.status_code, "data": r.json()}
        except: return {"status": r.status_code, "data": r.text[:300]}
    return await asyncio.get_event_loop().run_in_executor(None, _post)


@_action("ely_osint_scan", "Launch a Grey Team OSINT scan on a domain",
         {"profile_id": {"type": "string"}})
async def osint_scan(args, user_id):
    from greyteam.database import create_report as _create, get_profile
    profile = get_profile(args["profile_id"])
    if not profile:
        return {"error": "Profile not found"}
    rid = _create(profile_id=args["profile_id"], name="OSINT via Ely")
    # Spawn scan thread (same as greyteam/api.py)
    def _run():
        from greyteam.osint_scanner import OSINTDomainScanner
        from greyteam.database import add_finding, update_report
        domain = profile.get("target_domain", "")
        categories = profile.get("categories", "[]")
        if isinstance(categories, str):
            try: categories = json.loads(categories)
            except Exception: categories = []
        try:
            scanner = OSINTDomainScanner(domain=domain, modules=categories)
            findings = scanner.run_all()
            for f in findings:
                add_finding(report_id=rid, title=f.get("title", ""),
                    severity=f.get("severity", "medium"), category=f.get("category", ""),
                    description=f.get("description", ""), evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""), cwe_id=f.get("cwe_id", ""),
                    source="deterministic", finding_type=f.get("finding_type", "osint"))
            update_report(rid, status="completed")
        except Exception as e:
            update_report(rid, status="failed")
    threading.Thread(target=_run, daemon=True).start()
    return {"status": 200, "data": {"report_id": rid}}


@_action("ely_blueteam_analyze", "Launch a Blue Team security analysis on an API spec",
         {"profile_id": {"type": "string"}})
async def blueteam_analyze(args, user_id):
    from blueteam.database import create_report as _create, get_profile
    profile = get_profile(args["profile_id"])
    if not profile:
        return {"error": "Profile not found"}
    rid = _create(profile_id=args["profile_id"], report_md="Analysis via Ely")
    def _run():
        from blueteam.analyzer import BlueteamAnalyzer
        try:
            analyzer = BlueteamAnalyzer(report_id=rid, profile=profile)
            analyzer.run()
        except Exception:
            pass
    threading.Thread(target=_run, daemon=True).start()
    return {"status": 200, "data": {"report_id": rid}}


@_action("ely_create_workflow", "Create a new workflow",
         {"name": {"type": "string"}, "blocks": {"type": "string"}})
async def create_workflow(args, user_id):
    from database.workflow_graph_mgmt import save_workflow
    graph = args.get("blocks", "[]")
    if isinstance(graph, str):
        try: graph = json.loads(graph)
        except Exception: graph = {"blocks": []}
    wid = save_workflow(
        name=args["name"],
        graph=graph,
        user_id=user_id,
        description="Created by Ely",
    )
    return {"status": 200, "data": {"workflow_id": wid}}


@_action("ely_get_findings", "Get findings from a report",
         {"report_id": {"type": "string"},
          "team": {"type": "string", "enum": ["redteam", "greyteam", "blueteam"]}})
async def get_findings(args, user_id):
    team = args["team"]
    if team == "redteam":
        from redteam.database import get_campaign_findings as _get
    elif team == "greyteam":
        from greyteam.database import get_report_findings as _get
    else:
        from blueteam.database import get_report_findings as _get
    findings = _get(args["report_id"])
    return {"status": 200, "data": {"findings": findings, "total": len(findings)}}


@_action("ely_list_resources", "List resources (profiles, collections, workflows)",
         {"resource": {"type": "string", "enum": ["collections", "redteam_profiles",
                          "greyteam_profiles", "blueteam_profiles", "workflows"]}})
async def list_resources(args, user_id):
    r = args["resource"]
    try:
        if r == "collections":
            from database.collection_mgmt import get_collection_tree
            items = get_collection_tree(user_id=user_id)
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


# ═══════════════════════════════════════════════════════════════
# Registry
# ═══════════════════════════════════════════════════════════════

def get_action_definitions(page=None):
    all_defs = [v["definition"] for v in ACTIONS.values()]
    if not page:
        return all_defs
    page_actions = {
        "app":      ["ely_create_request", "ely_create_collection", "ely_list_resources"],
        "workflow": ["ely_create_workflow", "ely_list_resources"],
        "pentest":  ["ely_run_scan", "ely_get_findings", "ely_list_resources"],
        "greyteam": ["ely_osint_scan", "ely_get_findings", "ely_list_resources"],
        "blueteam": ["ely_blueteam_analyze", "ely_get_findings", "ely_list_resources"],
        "hub":      ["ely_list_resources", "ely_create_collection"],
        "doc":      [],
    }
    allowed = set(page_actions.get(page, []))
    return [d for d in all_defs if d.get("function", {}).get("name") in allowed or page is None]


async def execute_action(name, args, user_id=None, page=None, token=None):
    if name not in ACTIONS:
        return {"error": f"Unknown action: {name}"}
    handler = ACTIONS[name]["handler"]
    try:
        _log.info(f"Action '{name}' args={json.dumps(args, default=str)[:200]}")
        result = await handler(args, user_id, token)
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
