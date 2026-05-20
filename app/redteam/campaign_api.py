# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Pentest campaign API — FastAPI routes for managing pentest campaigns,
running scans, viewing findings, and generating reports.
"""

import asyncio
import threading
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response, StreamingResponse
from redteam.scan_events import publish, heartbeat, cleanup

from redteam.database import (
    init_pentest_db,
    create_campaign,
    list_campaigns,
    get_campaign,
    update_campaign_status,
    delete_campaign,
    add_finding,
    get_campaign_findings,
    get_finding_counts,
    add_scan_log,
    get_scan_logs,
    get_scan_log,
    get_finding_detail_log,
    create_profile,
    list_profiles,
    get_profile,
    update_profile,
    delete_profile,
    _now,
)
from redteam.scanner import Scanner
from redteam.report_generator import generate_report
from redteam.ai_enhancer import analyze_findings
from redteam.ai_scanner import AIScanner

import ipaddress
import json
import re
import sys
from urllib.parse import urlparse

app = APIRouter(prefix="/api/pentest", tags=["pentest"])

# Initialize DB on module load
init_pentest_db()


# ── Helpers ──

from database.auth_utils import get_auth_user, get_auth_user_teams
from core.auth import verify_ownership as _verify_ownership


# ── Scan Profiles CRUD ──

@app.post("/profiles")
async def api_create_profile(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    target_url = body.get("target_url", "").strip()
    if not name or not target_url:
        raise HTTPException(400, "name and target_url are required")
    team_ids = body.get("team_ids", "")
    if not team_ids:
        team_ids = get_auth_user_teams(request)
    pid = create_profile(
        name=name, target_url=target_url,
        user_id=get_auth_user(request), team_ids=team_ids,
        description=body.get("description", ""),
        auth_config=body.get("auth_config"),
        openapi_spec_url=body.get("openapi_spec_url", ""),
        id_list=body.get("id_list"),
        collection_id=body.get("collection_id", ""),
        explore_rounds=body.get("explore_rounds", 15),
        analysis_rounds=body.get("analysis_rounds", 5),
        expert_mode=body.get("expert_mode", 0),
        master_prompt=body.get("master_prompt", ""),
        documentation=body.get("documentation", ""),
    )
    # Store file content for later use
    spec_content = body.get("openapi_spec_content", "")
    if spec_content:
        _spec_cache[pid] = spec_content
    return {"profile_id": pid}


def _sanitize_profile(p):
    """Remove sensitive fields from profile for list/display."""
    for k in ("auth_config", "id_list", "master_prompt", "documentation"):
        p.pop(k, None)
    return p


@app.get("/profiles")
async def api_list_profiles(request: Request, team_id: str = ""):
    profiles = []
    if team_id == "__personal__":
        profiles = list_profiles(user_id=get_auth_user(request), personal_only=True)
    elif team_id:
        profiles = list_profiles(team_filter=team_id)
    else:
        profiles = list_profiles(user_id=get_auth_user(request), team_ids=get_auth_user_teams(request))
    return [_sanitize_profile(p) for p in profiles]


@app.get("/profiles/{profile_id}")
async def api_get_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p: raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    campaigns = list_campaigns(profile_id=profile_id, user_id=get_auth_user(request), team_ids=get_auth_user_teams(request))
    for c in campaigns:
        c["finding_counts"] = get_finding_counts(c["campaign_id"])
    p["campaigns"] = campaigns
    return p


@app.put("/profiles/{profile_id}")
async def api_update_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p: raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    body = await request.json()
    update_profile(profile_id, **{k: v for k, v in body.items() if v is not None})
    return {"status": "updated"}


@app.delete("/profiles/{profile_id}")
async def api_delete_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p: raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    delete_profile(profile_id)
    return {"status": "deleted"}


# ── Campaign CRUD (scoped to profile) ──

@app.get("/campaigns")
async def api_list_campaigns(request: Request, profile_id: str = ""):
    campaigns = list_campaigns(user_id=get_auth_user(request), team_ids=get_auth_user_teams(request), profile_id=profile_id)
    for c in campaigns:
        c.pop("auth_config", None)
        c.pop("id_list", None)
        c["finding_counts"] = get_finding_counts(c["campaign_id"])
    return campaigns


@app.get("/campaigns/{campaign_id}")
async def api_get_campaign(campaign_id: str, request: Request):
    c = get_campaign(campaign_id)
    if not c: raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    c["finding_counts"] = get_finding_counts(campaign_id)
    return c


@app.delete("/campaigns/{campaign_id}")
async def api_delete_campaign(campaign_id: str, request: Request):
    c = get_campaign(campaign_id)
    if not c: raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    delete_campaign(campaign_id)
    return {"status": "deleted"}


@app.post("/campaigns/{campaign_id}/stop")
async def api_stop_scan(campaign_id: str, request: Request):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    if campaign_id not in _running_scans and c.get("status") != "running":
        raise HTTPException(400, "No scan in progress for this campaign")
    _stop_flags[campaign_id] = True
    update_campaign_status(campaign_id, "stopped", c.get("scan_progress", 0))
    return {"status": "stopping"}


# ── Scan execution ──

# Track running scans, spec cache, and stop flags
_running_scans = {}
_spec_cache = {}
_stop_flags = {}
_scan_configs = {}


def _is_safe_url(url):
    """Block SSRF by rejecting URLs pointing to internal/private networks."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block raw IPs in private ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
                return False
            return True
        except ValueError:
            pass
        # Block cloud metadata endpoints and internal-only TLDs (configurable via app_config)
        from database.app_config import get as _cfg
        blocked_raw = _cfg("ssrf.blocked_hosts", "")
        blocked = [h.strip() for h in blocked_raw.split(",") if h.strip()] if blocked_raw else [
            "metadata.google.internal", "169.254.169.254",
            "instance-data", "169.254.170.2",
        ]
        if hostname.lower() in blocked:
            return False
        if hostname.lower().endswith(".local") or hostname.lower().endswith(".internal"):
            return False
        return True
    except Exception:
        return False



@app.post("/profiles/{profile_id}/scan")
async def api_start_scan(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    # Create campaign from profile
    user_id = get_auth_user(request)
    team_ids = get_auth_user_teams(request)
    scan_user_id = user_id  # captured for thread

    cid = create_campaign(
        name=f"{p['name']} — {_now()[:16]}",
        target_url=p["target_url"],
        user_id=user_id, team_ids=team_ids,
        description=p.get("description", ""),
        auth_config=p.get("auth_config"),
        openapi_spec_url=p.get("openapi_spec_url", ""),
        id_list=p.get("id_list"),
        collection_id=p.get("collection_id", ""),
        profile_id=profile_id,
    )
    campaign_id = cid
    if not cid:
        raise HTTPException(404, "Campaign not found")

    if campaign_id in _running_scans:
        raise HTTPException(400, "Scan already in progress for this campaign")

    # Capture user_id now — request is invalid inside background thread
    scan_user_id = get_auth_user(request)

    update_campaign_status(campaign_id, "running", 0)

    _stop_flags.pop(campaign_id, None)  # clear any previous stop flag

    def is_stopped():
        return _stop_flags.get(campaign_id, False)

    def progress_cb(pct, msg):
        update_campaign_status(campaign_id, "running", int(pct))
        publish(campaign_id, "progress", {"pct": int(pct), "msg": msg})

    def log_cb(**kwargs):
        add_scan_log(campaign_id=campaign_id, **kwargs)
        publish(campaign_id, "log", {
            "endpoint": kwargs.get("endpoint", ""),
            "method": kwargs.get("method", ""),
            "status": kwargs.get("response_status", 0),
            "check_name": kwargs.get("check_name", ""),
        })

    # ── Build collection_requests from OpenAPI spec, explicit collection, or both ──
    collection_requests = []

    # 1) Load OpenAPI spec → generate full requests via the existing parser
    spec_content = _spec_cache.pop(profile_id, None)
    if not spec_content:
        spec_url = p.get("openapi_spec_url", "")
        if spec_url:
            try:
                from core.security import validate_url_or_raise
                validate_url_or_raise(spec_url)
                import requests as req
                spec_resp = req.get(spec_url, timeout=15, allow_redirects=True)
                if spec_resp.status_code == 200:
                    spec_content = spec_resp.text
            except Exception:
                pass

    if spec_content:
        try:
            import yaml as _yaml
            spec_dict = json.loads(spec_content) if spec_content.strip().startswith("{") else _yaml.safe_load(spec_content)
            from doc_mgmt.openapi.parser import parse_openapi
            parsed = parse_openapi(spec_dict, server_url=p["target_url"])
            # Flatten all requests from all folders
            for folder in parsed.get("folders", []):
                for r in folder.get("requests", []):
                    collection_requests.append(r)
        except Exception:
            # Fallback: at least extract endpoints
            pass

    # 2) Also load explicit collection if selected
    collection_id = p.get("collection_id", "")
    if collection_id:
        if collection_requests:
            # if openapi and requests from collection both exist, prioritize collection for endpoints since it's more likely to be tailored by user
            collection_requests = []
        try:
            from database.collection_mgmt import get_collection_tree
            tree = get_collection_tree(author_user_id=get_auth_user(request))
            def _find_folder(nodes, fid):
                for n in nodes:
                    if n.get("id") == fid or n.get("folder_id") == fid:
                        return n
                    if n.get("children"):
                        r = _find_folder(n["children"], fid)
                        if r: return r
                return None
            def _collect(nodes):
                reqs = []
                for n in nodes:
                    if n.get("type") == "request":
                        reqs.append({"name": n.get("name", ""), "url": n.get("url", ""),
                                      "method": n.get("method", "GET"),
                                      "headers": n.get("headers", {}),
                                      "body": n.get("body", "")})
                    if n.get("children"):
                        reqs.extend(_collect(n["children"]))
                return reqs
            folder = _find_folder(tree, collection_id)
            if folder:
                collection_requests.extend(_collect(folder.get("children", []) if folder.get("type") == "folder" else [folder]))
        except Exception:
            pass

    def run_scan():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _run():
            auth_cfg = p.get("auth_config") or {}
            # Extract proxy from request JWT at scan start (no DB call needed later)
            from request_manager.request_api import _get_proxy_from_request
            px = _get_proxy_from_request(request)
            if px: auth_cfg["proxy"] = px.get("http") or px.get("https")
            scanner = Scanner(
                target_url=p["target_url"],
                auth_config=auth_cfg,
                progress_cb=progress_cb,
                log_cb=log_cb,
                id_list=p.get("id_list") or {},
                collection_requests=collection_requests,
            )
            # ── Phase 1: Deterministic scan ──
            findings = await scanner.run_all(stop_check=is_stopped)
            if is_stopped():
                update_campaign_status(campaign_id, "stopped", 50)
                publish(campaign_id, "done", {"status": "stopped"})
                _running_scans.pop(campaign_id, None)
                return
            for f in findings:
                add_finding(
                    campaign_id=campaign_id,
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    severity=f.get("severity", "info"),
                    category=f.get("category", ""),
                    endpoint=f.get("endpoint", ""),
                    method=f.get("method", "GET"),
                    evidence=f.get("evidence", {}),
                    remediation=f.get("remediation", ""),
                    cvss_score=f.get("cvss_score", 0.0),
                    cwe_id=f.get("cwe_id", ""),
                )

            update_campaign_status(campaign_id, "running", 60)
            progress_cb(60, "Phase 1 complete — AI deep scan starting...")

            if is_stopped():
                update_campaign_status(campaign_id, "stopped", 60)
                publish(campaign_id, "done", {"status": "stopped"})
                _running_scans.pop(campaign_id, None)
                return

            # ── Phase 2: AI deep scan ──
            log_cb(
                endpoint="AI Scanner", method="INIT", request_url=p["target_url"],
                response_status=0, response_body_preview="Starting AI deep scan...",
                response_time_ms=0, check_name="Phase 2 start",
            )
            try:
                existing = get_campaign_findings(campaign_id)

                def ai_on_finding(ai_f):
                    add_finding(
                        campaign_id=campaign_id,
                        title=f"[AI] {ai_f.get('title', '')}",
                        description=ai_f.get("description", ""),
                        severity=ai_f.get("severity", "info"),
                        category=ai_f.get("category", "AI Deep Scan"),
                        endpoint=ai_f.get("endpoint", ""),
                        method=ai_f.get("method", "GET"),
                        evidence=ai_f.get("evidence", {}),
                        remediation=ai_f.get("remediation", ""),
                        cvss_score=ai_f.get("cvss_score", 0.0),
                        cwe_id=ai_f.get("cwe_id", ""),
                        ai_analysis=ai_f.get("ai_analysis", ""),
                    )
                    publish(campaign_id, "finding", {
                        "title": ai_f.get("title", ""),
                        "severity": ai_f.get("severity", "info"),
                        "endpoint": ai_f.get("endpoint", ""),
                    })

                expert_mode = p.get("expert_mode") == 1 or p.get("expert_mode") is True
                scanner_cls = AIScanner
                scanner_kwargs = dict(
                    campaign_id=campaign_id,
                    target_url=p["target_url"],
                    user_id=scan_user_id,
                    auth_config=p.get("auth_config") or {},
                    deterministic_findings=existing,
                    collection_requests=collection_requests,
                    id_list=p.get("id_list") or {},
                    description=p.get("description", ""),
                    explore_rounds=p.get("explore_rounds", 30 if expert_mode else 15),
                    analysis_rounds=p.get("analysis_rounds", 15 if expert_mode else 5),
                    callbacks={"on_log": log_cb, "on_finding": ai_on_finding, "on_progress": progress_cb},
                    stop_check=lambda: _stop_flags.get(campaign_id, False),
                )
                if expert_mode:
                    from redteam.expert_scanner import ExpertAIScanner
                    scanner_cls = ExpertAIScanner
                    scanner_kwargs["master_prompt"] = p.get("master_prompt", "")
                    scanner_kwargs["documentation"] = p.get("documentation", "")
                    scanner_kwargs["openapi_spec"] = (p.get("openapi_spec_url") or "").strip()
                ai_scanner = scanner_cls(**scanner_kwargs)
                ai_result = await ai_scanner.run()
                ai_findings = ai_result.get("findings", []) if isinstance(ai_result, dict) else ai_result
                _scan_configs[campaign_id] = {
                    "flash_model": ai_result.get("flash_model", "N/A"),
                    "pro_model": ai_result.get("pro_model", "N/A"),
                    "explore_rounds": ai_result.get("explore_rounds", 0),
                    "analysis_rounds": ai_result.get("analysis_rounds", 0),
                    "tokens": ai_result.get("tokens", {}),
                } if isinstance(ai_result, dict) else {}

                conv_len = len(getattr(ai_scanner, 'conversation', []) or [])
                log_cb(
                    endpoint="AI Scanner", method="DONE", request_url="",
                    response_status=200,
                    response_body_preview=f"AI scan completed. Rounds: {conv_len}. Findings: {len(ai_findings)}.",
                    response_time_ms=0, check_name="Phase 2 complete",
                )

                if not ai_findings:
                    add_finding(
                        campaign_id=campaign_id,
                        title="AI deep scan completed — no new findings",
                        description=f"The AI analyzed the API ({len(getattr(ai_scanner, 'conversation', []) or [])} conversation rounds) but did not identify additional vulnerabilities beyond the deterministic scan.",
                        severity="info",
                        category="Scanner Info",
                    )
            except Exception as e:
                import traceback
                err_msg = f"{type(e).__name__}: {str(e)[:300]}"
                trace = traceback.format_exc()
                # Write to file since stderr doesn't reach console from daemon thread
                with open("pentest_ai_error.log", "w") as f:
                    f.write(f"AI DEEP SCAN FAILED: {err_msg}\n\n{trace}\n")
                log_cb(
                    endpoint="AI Scanner", method="ERROR", request_url="",
                    response_status=0, response_body_preview=traceback.format_exc()[:2000],
                    response_time_ms=0, check_name=f"AI setup failed: {err_msg}",
                )
                add_finding(
                    campaign_id=campaign_id,
                    title="AI deep scan skipped",
                    description=f"The AI-powered deep scan could not complete.\n\nError: {err_msg}\n\nCheck that AI provider env vars are set (OPENAI_API_KEY or DEEPSEEK_API_KEY). Deterministic scan results are still available.",
                    severity="info",
                    category="Scanner Info",
                )

            # Store AI config in campaign
            ai_cfg = _scan_configs.get(campaign_id, {})
            try:
                from redteam.database import _connect
                conn = _connect()
                conn.execute(
                    "UPDATE pentest_campaigns SET flash_model=?, pro_model=?, tokens_used=? WHERE campaign_id=?",
                    (ai_cfg.get("flash_model", ""), ai_cfg.get("pro_model", ""),
                     ai_cfg.get("tokens", {}).get("total", 0), campaign_id),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

            update_campaign_status(campaign_id, "completed", 100)
            publish(campaign_id, "done", {"status": "completed", "tokens": ai_cfg.get("tokens", {}).get("total", 0)})
            _running_scans.pop(campaign_id, None)

        try:
            loop.run_until_complete(_run())
        except Exception as e:
            import traceback
            err = f"{type(e).__name__}: {str(e)[:300]}"
            try:
                with open("pentest_scan_error.log", "w") as f:
                    f.write(f"SCAN CRASHED: {err}\n\n{traceback.format_exc()}\n")
            except Exception:
                pass
            try:
                update_campaign_status(campaign_id, "failed", 0)
                publish(campaign_id, "done", {"status": "failed", "error": err})
            except Exception:
                pass
            _running_scans.pop(campaign_id, None)
        cleanup(campaign_id)

    # Resolve AI models now so we can return them immediately
    from database.ai_config_mgmt import get_default_config
    def _resolve_model(slot, fallback):
        cfg = get_default_config(slot)
        if cfg: return cfg.get("model") or fallback
        return fallback

    flash_model = _resolve_model("flash", "gpt-4o-mini")
    pro_model = _resolve_model("pro", "gpt-4o")

    # Store AI models in campaign now so they're visible immediately
    try:
        from redteam.database import _connect
        conn = _connect()
        conn.execute(
            "UPDATE pentest_campaigns SET flash_model=?, pro_model=? WHERE campaign_id=?",
            (flash_model, pro_model, campaign_id),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    _running_scans[campaign_id] = True
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return {
        "status": "scan_started",
        "campaign_id": campaign_id,
        "flash_model": flash_model,
        "pro_model": pro_model,
    }


# ── Findings ──

@app.get("/campaigns/{campaign_id}/findings")
async def api_get_findings(campaign_id: str, request: Request):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    findings = get_campaign_findings(campaign_id)
    return findings


# ── Scan Logs ──

@app.get("/campaigns/{campaign_id}/logs")
async def api_get_scan_logs(request: Request, campaign_id: str, limit: int = 50, page: int = 1):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    return get_scan_logs(campaign_id, limit=limit, page=page)

@app.get("/campaigns/{campaign_id}/logs/{log_id}")
async def api_get_scan_log(request: Request, campaign_id: str, log_id: str):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    log = get_scan_log(log_id)
    if not log or log.get("campaign_id") != campaign_id:
        raise HTTPException(404, "Log not found")
    return log

@app.get("/campaigns/{campaign_id}/findings/{finding_id}/details")
async def api_get_finding_details(request: Request, campaign_id: str, finding_id: str):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    log = get_finding_detail_log(campaign_id, finding_id)
    if not log:
        raise HTTPException(404, "No matching log found")
    return log


# ── Report ──

@app.get("/campaigns/{campaign_id}/report")
async def api_get_report(request: Request, campaign_id: str, format: str = "json"):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))

    findings = get_campaign_findings(campaign_id)
    findings_raw = []
    for f in findings:
        d = dict(f)
        if isinstance(d.get("evidence"), str):
            import json
            try:
                d["evidence"] = json.loads(d["evidence"])
            except Exception:
                pass
        findings_raw.append(d)

    scan_config = _scan_configs.get(campaign_id, {})

    # Collect AI insights from any finding that has them
    ai_insights = ""
    for f in findings_raw:
        if f.get("ai_analysis"):
            ai_insights = f["ai_analysis"]
            break

    # Collect matching logs for each finding
    finding_logs = {}
    for f in findings_raw:
        log = get_finding_detail_log(campaign_id, f.get("finding_id"))
        if log:
            finding_logs[f["finding_id"]] = log

    standard_md = generate_report(c, findings_raw, ai_insights, finding_logs, scan_config)
    expert_md = c.get("expert_report") or ""

    if format == "md" or format == "markdown":
        return Response(content=standard_md, media_type="text/markdown")

    if format == "expert":
        if not expert_md:
            raise HTTPException(404, "No expert report available for this campaign")
        return Response(content=expert_md, media_type="text/markdown")

    safe_campaign = dict(c)
    safe_campaign.pop("auth_config", None)
    return {
        "campaign": safe_campaign,
        "findings": findings_raw,
        "finding_counts": get_finding_counts(campaign_id),
        "finding_logs": finding_logs,
        "scan_config": scan_config,
        "report_markdown": standard_md,
        "expert_report": expert_md,
    }


@app.get("/campaigns/{campaign_id}/expert-report")
async def api_get_expert_report(request: Request, campaign_id: str, format: str = "html"):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    report = c.get("expert_report") or ""
    if not report:
        raise HTTPException(404, "No expert report available for this campaign")
    if format == "md" or format == "markdown":
        return Response(content=report, media_type="text/markdown",
                        headers={"Content-Disposition": "attachment; filename=expert-report.md"})
    # Return as HTML rendered from markdown
    return {"report_markdown": report, "campaign_name": c.get("name", "")}
