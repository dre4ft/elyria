"""
Blue Team API — FastAPI routes for SSDLC security analysis profiles and reports.
"""

import json
import threading

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, Response, StreamingResponse
from redteam.scan_events import publish, cleanup as events_cleanup

from blueteam.database import (
    init_blueteam_db, create_profile, list_profiles, get_profile,
    update_profile, delete_profile, create_report, get_reports, get_report,
)
from blueteam.ssdlc_scanner import SSDLCAnalyzer

app = APIRouter(prefix="/api/blueteam")
init_blueteam_db()

_spec_cache = {}  # profile_id → openapi spec content
_running = set()  # profile_ids currently analyzing
_analysis_progress = {}  # profile_id → {"pct": int, "msg": str, "status": str}


from database.auth_utils import get_auth_user, get_auth_user_teams


from core.auth import verify_ownership as _verify_ownership


# ═══════════════════════════════════════════
# PROFILES
# ═══════════════════════════════════════════

@app.post("/profiles/{profile_id}/stop")
async def api_stop_analysis(profile_id: str, request: Request):
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    _analysis_progress.pop(profile_id, None)
    _running.discard(profile_id)
    update_profile(profile_id, status="stopped")
    publish(profile_id, "done", {"status": "stopped"})
    return {"status": "stopped"}

@app.post("/profiles")
async def api_create_profile(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    target_url = body.get("target_url", "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    team_ids = body.get("team_ids", "")
    if not team_ids:
        team_ids = get_auth_user_teams(request)
    pid = create_profile(
        name=name, target_url=target_url,
        user_id=get_auth_user(request), team_ids=team_ids,
        description=body.get("description", ""),
        master_prompt=body.get("master_prompt", ""),
        documentation=body.get("documentation", ""),
        openapi_spec_url=body.get("openapi_spec_url", ""),
        collection_id=body.get("collection_id", ""),
    )
    # Cache OpenAPI spec content for later use
    spec_content = body.get("openapi_spec_content", "")
    if spec_content:
        _spec_cache[pid] = spec_content
    return {"profile_id": pid}


@app.get("/profiles")
async def api_list_profiles(request: Request, team_id: str = ""):
    if team_id:
        return list_profiles(team_filter=team_id)
    return list_profiles(user_id=get_auth_user(request), team_ids=get_auth_user_teams(request))


@app.get("/profiles/{profile_id}")
async def api_get_profile(profile_id: str, request: Request):
    """Full profile — use only when selecting/displaying a profile."""
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    p["reports"] = get_reports(profile_id)
    prog = _analysis_progress.get(profile_id, {})
    p["progress_msg"] = prog.get("msg", "")
    if prog.get("pct"):
        p["scan_progress"] = prog["pct"]
    return p


@app.get("/profiles/{profile_id}/status")
async def api_get_profile_status(profile_id: str, request: Request):
    """Lightweight — only status + progress. Uses in-memory dict for coherence."""
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    prog = _analysis_progress.get(profile_id, {})
    return {
        "profile_id": p["profile_id"],
        "status": p.get("status", "pending"),
        "scan_progress": prog.get("pct", p.get("scan_progress", 0)),
        "pro_model": p.get("pro_model", ""),
        "progress_msg": prog.get("msg", ""),
    }


@app.put("/profiles/{profile_id}")
async def api_update_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    body = await request.json()
    update_profile(profile_id, **{k: v for k, v in body.items() if v is not None})
    return {"status": "updated"}


@app.delete("/profiles/{profile_id}")
async def api_delete_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    delete_profile(profile_id)
    return {"status": "deleted"}


# ═══════════════════════════════════════════
# CROSS-FEATURE — Import from Pentest
# ═══════════════════════════════════════════

@app.post("/import-from-pentest")
async def api_import_from_pentest(request: Request):
    """Create a Blue Team remediation analysis from a Red Team pentest campaign."""
    body = await request.json()
    campaign_id = body.get("campaign_id", "").strip()
    if not campaign_id:
        raise HTTPException(400, "campaign_id is required")

    # Fetch campaign data — verify ownership
    try:
        from redteam.database import get_campaign, get_campaign_findings
        c = get_campaign(campaign_id)
        if not c:
            raise HTTPException(404, "Campaign not found")
        _verify_ownership(c, get_auth_user(request), get_auth_user_teams(request))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(404, "Campaign not found")

    findings = body.get("findings") or get_campaign_findings(campaign_id) or []

    # Build documentation from pentest report + findings
    findings_text = "\n".join(
        f"- [{f.get('severity','?')}] {f.get('title','')} | {f.get('endpoint','')} {f.get('method','')}\n  Impact: {f.get('description','')[:200]}\n  Remediation: {f.get('remediation','')[:200]}"
        for f in (findings if isinstance(findings, list) else [])
    )

    documentation = f"""# Rapport de Pentest importe
Campagne: {c.get('name','')}
Cible: {c.get('target_url','')}
Date: {c.get('created_at','')}
Statut: {c.get('status','')}

## Findings detectes ({len(findings) if isinstance(findings, list) else 0})
{findings_text}
"""

    master_prompt = f"""Tu es un expert en remediation de securite. Tu viens de recevoir le rapport d'un pentest (Red Team) realise sur l'API {c.get('target_url','')}.

TA MISSION:
1. Analyser chaque finding du pentest
2. Pour chaque vulnérabilite, proposer un plan de remediation concret et priorise
3. Rediger un rapport de remediation actionnable pour l'equipe de developpement
4. Classer les actions par priorite (immediat, court terme, moyen terme)
5. Inclure des exemples de code et des references (OWASP, NIST)
6. Utilise des diagrammes Mermaid (\`\`\`mermaid) pour illustrer les flux d'attaque, l'architecture cible, et les plans de remediation

Le rapport original du pentest est fourni dans la documentation ci-dessous."""

    user_id = get_auth_user(request)
    pid = create_profile(
        name=f"Remediation — {c.get('name','Pentest')[:50]}",
        target_url=c.get('target_url', ''),
        user_id=user_id,
        team_ids=get_auth_user_teams(request),
        description=f"Analyse de remediation importee depuis le pentest (campagne {campaign_id[:8]}...)",
        master_prompt=master_prompt,
        documentation=documentation,
        source_type="pentest",
        source_id=campaign_id,
    )

    # Start analysis immediately
    from database.ai_config_mgmt import get_default_config
    pro_cfg = get_default_config("pro")
    pro_model = pro_cfg.get("model") if pro_cfg else "gpt-4o"
    update_profile(pid, status="running", pro_model=pro_model)

    def _progress(pct, msg):
        _analysis_progress[pid] = {"pct": pct, "msg": msg, "status": "running"}
        update_profile(pid, status="running", scan_progress=pct)
        publish(pid, "progress", {"pct": pct, "msg": msg})

    _running.add(pid)

    def run_analysis():
        try:
            from blueteam.ssdlc_scanner import SSDLCAnalyzer
            analyzer = SSDLCAnalyzer(
                target_url=c.get("target_url", ""),
                user_id=user_id,
                master_prompt=master_prompt,
                documentation=documentation,
                openapi_spec="",
                collection_requests=[],
                callbacks={"on_progress": _progress},
                analysis_rounds=6,
                report_rounds=4,
            )
            result = analyzer.run()
            create_report(
                profile_id=pid,
                report_md=result["report_markdown"],
                findings_count=result["findings_count"],
                analysis_rounds=result["analysis_rounds"],
                tokens_used=result["tokens"].get("total", 0),
                pro_model=result["pro_model"],
            )
            update_profile(pid, status="completed", tokens_used=result["tokens"].get("total", 0))
            publish(pid, "done", {"status": "completed"})
        except Exception as e:
            update_profile(pid, status="failed")
            publish(pid, "done", {"status": "failed"})
        finally:
            _running.discard(pid)
            events_cleanup(pid)

    print(f"[BLUETEAM] Starting remediation analysis for pentest import, profile={pid}", flush=True)
    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()

    return {"status": "started", "profile_id": pid, "pro_model": pro_model}


# ═══════════════════════════════════════════
# ANALYSIS
# ═══════════════════════════════════════════

@app.post("/profiles/{profile_id}/analyze")
async def api_start_analysis(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))

    if profile_id in _running:
        raise HTTPException(400, "Analysis already in progress for this profile")

    scan_user_id = get_auth_user(request)

    # Resolve pro model
    from database.ai_config_mgmt import get_default_config
    pro_cfg = get_default_config("pro")
    pro_model = pro_cfg.get("model") if pro_cfg else "gpt-4o"
    update_profile(profile_id, status="running", pro_model=pro_model)

    # Load spec content
    spec_content = _spec_cache.pop(profile_id, None)
    if not spec_content:
        spec_url = p.get("openapi_spec_url", "")
        if spec_url:
            try:
                import requests as req
                r = req.get(spec_url, timeout=15, allow_redirects=True)
                if r.status_code == 200:
                    spec_content = r.text
            except Exception:
                pass

    # Load collection
    collection_requests = []
    collection_id = p.get("collection_id", "")
    if collection_id:
        try:
            from database.collection_mgmt import get_collection_tree
            tree = get_collection_tree(author_user_id=get_auth_user(request))
            def _find(nodes, fid):
                for n in nodes:
                    if n.get("id") == fid or n.get("folder_id") == fid:
                        return n
                    if n.get("children"):
                        r = _find(n["children"], fid)
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
            folder = _find(tree, collection_id)
            if folder:
                collection_requests.extend(_collect(
                    folder.get("children", []) if folder.get("type") == "folder" else [folder]
                ))
        except Exception:
            pass

    def _progress(pct, msg):
        _analysis_progress[profile_id] = {"pct": pct, "msg": msg, "status": "running"}
        update_profile(profile_id, status="running", scan_progress=pct)
        publish(profile_id, "progress", {"pct": pct, "msg": msg})

    _running.add(profile_id)

    def run_analysis():
        try:
            analyzer = SSDLCAnalyzer(
                target_url=p["target_url"],
                user_id=scan_user_id,
                master_prompt=p.get("master_prompt", ""),
                documentation=p.get("documentation", ""),
                openapi_spec=spec_content or "",
                collection_requests=collection_requests,
                callbacks={"on_progress": _progress},
                analysis_rounds=8,
                report_rounds=5,
            )
            result = analyzer.run()
            create_report(
                profile_id=profile_id,
                report_md=result["report_markdown"],
                findings_count=result["findings_count"],
                analysis_rounds=result["analysis_rounds"],
                tokens_used=result["tokens"].get("total", 0),
                pro_model=result["pro_model"],
            )
            update_profile(profile_id, status="completed", tokens_used=result["tokens"].get("total", 0))
            publish(profile_id, "done", {"status": "completed", "tokens": result["tokens"].get("total", 0)})
        except Exception as e:
            import traceback
            try:
                with open("blueteam_error.log", "w") as f:
                    f.write(f"BLUE TEAM ANALYSIS FAILED: {e}\n\n{traceback.format_exc()}\n")
            except Exception:
                pass
            update_profile(profile_id, status="failed")
            publish(profile_id, "done", {"status": "failed"})
        finally:
            _running.discard(profile_id)
            events_cleanup(profile_id)

    print(f"[BLUETEAM] Starting analysis thread for profile {profile_id}, model={pro_model}", flush=True)
    thread = threading.Thread(target=run_analysis, daemon=True)
    thread.start()

    return {"status": "started", "profile_id": profile_id, "pro_model": pro_model}


# ═══════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════

@app.get("/profiles/{profile_id}/reports")
async def api_list_reports(profile_id: str, request: Request):
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    return get_reports(profile_id)


@app.get("/reports/{report_id}")
async def api_get_report(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    p = get_profile(r["profile_id"])
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    return r


@app.get("/reports/{report_id}/download")
async def api_download_report(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    p = get_profile(r["profile_id"])
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    return Response(
        content=r["report_markdown"],
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=ssdlc-report-{report_id[:8]}.md"},
    )
