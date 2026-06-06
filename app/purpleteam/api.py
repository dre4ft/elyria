# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Purple Team API — FastAPI routes for IAST code security analysis.
"""

import json
import threading
from core.logging import get_logger
from fastapi import APIRouter, Request, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, Response

_log = get_logger("purpleteam.api")

from database.auth_utils import get_auth_user, get_auth_user_teams
from core.auth import verify_ownership as _verify_ownership

from purpleteam.database import (
    init_purpleteam_db, create_profile, list_profiles, get_profile,
    update_profile, delete_profile, create_scan, get_scan, list_scans,
    update_scan, delete_scan, add_finding, get_scan_findings,
    get_finding_counts,
)

app = APIRouter(prefix="/api/purpleteam")
init_purpleteam_db()

_running = set()
_progress = {}


# ═══════════════════════════════════════════
# PROFILES
# ═══════════════════════════════════════════

@app.post("/profiles")
async def api_create_profile(request: Request):
    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        raise HTTPException(400, "name is required")
    team_ids = body.get("team_ids", "") or get_auth_user_teams(request)
    pid = create_profile(
        name=name,
        repo_source=body.get("repo_source", "github"),
        repo_url=body.get("repo_url", ""),
        repo_auth_type=body.get("repo_auth_type", ""),
        repo_auth_key=body.get("repo_auth_key", ""),
        repo_branch=body.get("repo_branch", "main"),
        target_endpoint=body.get("target_endpoint", ""),
        openapi_spec_url=body.get("openapi_spec_url", ""),
        collection_id=body.get("collection_id", ""),
        user_id=get_auth_user(request),
        team_ids=team_ids,
        description=body.get("description", ""),
        scan_depth=body.get("scan_depth", "full"),
    )
    return {"profile_id": pid}


@app.get("/profiles")
async def api_list_profiles(request: Request, team_id: str = ""):
    profiles = list_profiles(team_filter=team_id) if team_id else list_profiles(user_id=get_auth_user(request), team_ids=get_auth_user_teams(request))
    # Attach finding counts per profile
    for p in profiles:
        scans = list_scans(profile_id=p["profile_id"])
        total_counts = {}
        for s in scans:
            counts = get_finding_counts(s["scan_id"])
            for sev, cnt in counts.items():
                total_counts[sev] = total_counts.get(sev, 0) + cnt
        p["finding_counts"] = total_counts
        p["total_findings"] = sum(total_counts.values())
    return profiles


@app.get("/profiles/{profile_id}")
async def api_get_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    p["scans"] = list_scans(profile_id=profile_id)
    prog = _progress.get(profile_id, {})
    p["progress_msg"] = prog.get("msg", "")
    p["scan_progress"] = prog.get("pct", p.get("scan_progress", 0))
    return p


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
# SCAN
# ═══════════════════════════════════════════

@app.post("/profiles/{profile_id}/scan")
async def api_start_scan(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))

    if profile_id in _running:
        raise HTTPException(400, "Scan already in progress for this profile")

    scan_user_id = get_auth_user(request)
    scan_depth = p.get("scan_depth", "full")

    sid = create_scan(
        profile_id=profile_id,
        name=f"Scan — {p['name']}",
        repo_source=p.get("repo_source", "github"),
        repo_url=p.get("repo_url", ""),
        repo_auth_type=p.get("repo_auth_type", ""),
        repo_auth_key=p.get("repo_auth_key", ""),
        repo_branch=p.get("repo_branch", "main"),
        target_endpoint=p.get("target_endpoint", ""),
        openapi_spec_url=p.get("openapi_spec_url", ""),
        collection_id=p.get("collection_id", ""),
        user_id=scan_user_id,
        team_ids=p.get("team_ids", ""),
        scan_depth=scan_depth,
    )

    def _progress_fn(pct, msg):
        _progress[profile_id] = {"pct": pct, "msg": msg, "status": "running"}
        update_scan(sid, scan_progress=pct, phase=msg)

    _running.add(profile_id)

    def run_scan():
        repo_path = ""
        try:
            # Phase 0: Clone/fetch repo
            repo_source = p.get("repo_source", "github")
            repo_url = p.get("repo_url", "")
            repo_auth_type = p.get("repo_auth_type", "")
            repo_auth_key = p.get("repo_auth_key", "")
            repo_branch = p.get("repo_branch", "main")

            if repo_source == "local":
                if repo_url and repo_url.strip():
                    _progress_fn(2, "Using local repository...")
                    repo_path = repo_url.strip()
                    import os
                    if not os.path.isdir(repo_path):
                        raise ValueError(f"Local directory not found: {repo_path}")
                else:
                    raise ValueError("Local repo selected but no path provided")
            elif repo_url:
                _progress_fn(2, f"Cloning repository ({repo_source})...")
                from purpleteam.repo_manager import clone_repo
                repo_path = clone_repo(repo_url, scan_user_id, repo_auth_type, repo_auth_key, repo_branch)
                update_scan(sid, repo_path=repo_path)
            else:
                raise ValueError("No repository URL or path provided")

            # Detect language
            from purpleteam.repo_manager import detect_language, parse_dependencies
            language, framework = detect_language(repo_path)

            _progress_fn(5, f"Detected: {language}/{framework}")

            # ── Phase 1: Static Analysis ──
            _progress_fn(8, "Starting static analysis...")
            from purpleteam.static_scanner import StaticScanner
            static = StaticScanner(repo_path, scan_user_id)
            static_count = static.run(sid, add_finding, _progress_fn)
            _log.info(f"Static analysis: {static_count} findings")

            # ── Phase 2: Dynamic IAST Testing ──
            dynamic_count = 0
            target_endpoint = p.get("target_endpoint", "")
            if target_endpoint and scan_depth in ("full", "iast"):
                _progress_fn(85, "Starting dynamic IAST testing...")
                from purpleteam.dynamic_scanner import DynamicScanner
                auth_config = {}
                if p.get("repo_auth_type") == "bearer" and p.get("repo_auth_key"):
                    auth_config["bearer_token"] = p["repo_auth_key"]
                dynamic = DynamicScanner(target_endpoint, auth_config=auth_config)
                dynamic_count = dynamic.run(sid, add_finding, _progress_fn)
                _log.info(f"Dynamic testing: {dynamic_count} findings")

            # ── Phase 3: AI Deep Analysis ──
            ai_count = 0
            tokens = {}
            models = {}
            if scan_depth in ("full", "iast"):
                _progress_fn(88, "Starting AI deep code analysis...")
                try:
                    from purpleteam.ai_scanner import AIPurpleScanner
                    static_findings = get_scan_findings(sid)
                    ai = AIPurpleScanner(repo_path, target_endpoint, scan_user_id, static_findings)
                    ai_count = ai.run(sid, add_finding, _progress_fn)
                    tokens = ai.get_tokens()
                    models = ai.get_models()
                    update_scan(sid, tokens_used=tokens.get("total", 0),
                               flash_model=models.get("flash", ""),
                               pro_model=models.get("pro", ""))
                    _log.info(f"AI analysis: {ai_count} findings")
                except Exception as e:
                    _log.warning(f"AI analysis skipped: {e}")

            total = static_count + dynamic_count + ai_count
            update_scan(sid, status="completed", scan_progress=100)
            _progress[profile_id] = {"pct": 100, "msg": "Complete", "status": "completed",
                                      "total_findings": total, "language": language, "framework": framework,
                                      "tokens": tokens, "models": models}
            _log.info(f"Purple Team scan complete: {total} findings")

        except Exception as e:
            import traceback
            _log.error(f"Purple Team scan failed: {e}\n{traceback.format_exc()}")
            update_scan(sid, status="failed")
            _progress[profile_id] = {"pct": 0, "msg": "Failed", "status": "failed", "error": str(e)}
        finally:
            _running.discard(profile_id)

    _log.info(f"Starting Purple Team scan thread for profile={profile_id}, scan={sid}")
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return {"status": "started", "scan_id": sid}


@app.post("/profiles/{profile_id}/stop")
async def api_stop_scan(profile_id: str, request: Request):
    p = get_profile(profile_id)
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    _progress.pop(profile_id, None)
    _running.discard(profile_id)
    update_profile(profile_id, status="stopped")
    return {"status": "stopped"}


# ═══════════════════════════════════════════
# SCANS LIST / DETAIL
# ═══════════════════════════════════════════

@app.get("/scans")
async def api_list_scans(request: Request, profile_id: str = ""):
    return list_scans(
        user_id=get_auth_user(request),
        team_ids=get_auth_user_teams(request),
        profile_id=profile_id or None,
    )


@app.get("/scans/{scan_id}")
async def api_get_scan(scan_id: str, request: Request):
    s = get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    _verify_ownership(s, get_auth_user(request), get_auth_user_teams(request))
    s["findings"] = get_scan_findings(scan_id)
    s["finding_counts"] = get_finding_counts(scan_id)
    prog = _progress.get(s.get("profile_id", ""), {})
    s["progress_msg"] = prog.get("msg", "")
    return s


@app.delete("/scans/{scan_id}")
async def api_delete_scan(scan_id: str, request: Request):
    s = get_scan(scan_id)
    _verify_ownership(s, get_auth_user(request), get_auth_user_teams(request))
    # Clean up cloned repo
    repo_path = s.get("repo_path", "")
    if repo_path:
        try:
            from purpleteam.repo_manager import cleanup_repo
            cleanup_repo(repo_path)
        except Exception:
            pass
    delete_scan(scan_id)
    return {"status": "deleted"}


# ═══════════════════════════════════════════
# FINDINGS
# ═══════════════════════════════════════════

@app.get("/scans/{scan_id}/findings")
async def api_get_findings(scan_id: str, request: Request):
    s = get_scan(scan_id)
    _verify_ownership(s, get_auth_user(request), get_auth_user_teams(request))
    return get_scan_findings(scan_id)


# ═══════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════

@app.get("/scans/{scan_id}/report")
async def api_get_report(scan_id: str, request: Request):
    s = get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    _verify_ownership(s, get_auth_user(request), get_auth_user_teams(request))
    findings = get_scan_findings(scan_id)
    from purpleteam.report_generator import generate_report
    from purpleteam.repo_manager import detect_language
    language, framework = "unknown", "unknown"
    repo_path = s.get("repo_path", "")
    if repo_path and __import__("os").path.isdir(repo_path):
        language, framework = detect_language(repo_path)
    report_md = generate_report(s, findings, {
        "language": language,
        "framework": framework,
        "flash_model": s.get("flash_model", ""),
        "pro_model": s.get("pro_model", ""),
        "tokens": {"total": s.get("tokens_used", 0)},
    })
    return {"scan_id": scan_id, "report_markdown": report_md}


@app.get("/scans/{scan_id}/report/download")
async def api_download_report(scan_id: str, request: Request):
    s = get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    _verify_ownership(s, get_auth_user(request), get_auth_user_teams(request))
    findings = get_scan_findings(scan_id)
    from purpleteam.report_generator import generate_report
    from purpleteam.repo_manager import detect_language
    language, framework = "unknown", "unknown"
    repo_path = s.get("repo_path", "")
    if repo_path and __import__("os").path.isdir(repo_path):
        language, framework = detect_language(repo_path)
    report_md = generate_report(s, findings, {
        "language": language,
        "framework": framework,
        "flash_model": s.get("flash_model", ""),
        "pro_model": s.get("pro_model", ""),
        "tokens": {"total": s.get("tokens_used", 0)},
    })
    safe_name = s.get("name", "report").replace(" ", "_")[:50]
    return Response(
        content=report_md,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=purpleteam-{safe_name}-{scan_id[:8]}.md"},
    )


# ═══════════════════════════════════════════
# SEND TO BLUE TEAM
# ═══════════════════════════════════════════

@app.post("/scans/{scan_id}/send-to-blueteam")
async def api_send_to_blueteam(scan_id: str, request: Request):
    """Send Purple Team findings to Blue Team for remediation analysis."""
    s = get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    _verify_ownership(s, get_auth_user(request), get_auth_user_teams(request))

    findings = get_scan_findings(scan_id)
    if not findings:
        raise HTTPException(400, "No findings to send")

    # Build documentation from Purple Team report
    from purpleteam.report_generator import generate_report
    from purpleteam.repo_manager import detect_language
    import os
    language, framework = "unknown", "unknown"
    repo_path = s.get("repo_path", "")
    if repo_path and os.path.isdir(repo_path):
        language, framework = detect_language(repo_path)

    report_md = generate_report(s, findings, {
        "language": language,
        "framework": framework,
        "flash_model": s.get("flash_model", ""),
        "pro_model": s.get("pro_model", ""),
        "tokens": {"total": s.get("tokens_used", 0)},
    })

    findings_text = "\n".join(
        f"- [{f.get('severity','?')}] {f.get('title','')} | {f.get('file_path','')} | CVE: {f.get('cve_id','-')} | CWE: {f.get('cwe_id','-')}"
        for f in findings[:100]
    )

    documentation = f"""# Rapport Purple Team importe

Scan: {s.get('name','')}
Repository: {s.get('repo_url','')}
Target: {s.get('target_endpoint','')}
Language: {language}/{framework}
Date: {s.get('created_at','')}

## Rapport complet

{report_md}

## Findings summary ({len(findings)})

{findings_text}
"""

    master_prompt = f"""Tu es un expert en remediation de securite. Tu viens de recevoir le rapport d'une analyse Purple Team (IAST — analyse statique + dynamique) realisee sur le depot {s.get('repo_url','')}.

L'analyse Purple Team combine:
1. **SAST** — Analyse statique du code source (CVE, CWE, mauvaises pratiques)
2. **DAST** — Tests dynamiques contre l'API cible (validation des vulnerabilites)
3. **IA** — Deep code review avec lecture du code source et requetes HTTP

TA MISSION:
1. Analyser chaque finding du rapport Purple Team
2. Pour chaque vulnerabilite, proposer un plan de remediation concret et priorise
3. Rediger un rapport de remediation actionnable pour l'equipe de developpement
4. Classer les actions par priorite (immediat, court terme, moyen terme)
5. Inclure des exemples de code corrige et des references (OWASP, NIST, CWE)
6. Utilise des diagrammes Mermaid (```mermaid) pour illustrer les correctifs architecturaux

Le rapport complet de la Purple Team est fourni dans la documentation ci-dessous."""

    try:
        from blueteam.database import create_profile as bt_create_profile, update_profile as bt_update_profile, create_report as bt_create_report
        from database.ai_config_mgmt import get_default_config

        user_id = get_auth_user(request)
        pid = bt_create_profile(
            name=f"Purple Team Remediation — {s.get('name','Scan')[:50]}",
            target_url=s.get('repo_url', ''),
            user_id=user_id,
            team_ids=get_auth_user_teams(request),
            description=f"Analyse de remediation importee depuis Purple Team (scan {scan_id[:8]})",
            master_prompt=master_prompt,
            documentation=documentation,
            source_type="purpleteam",
            source_id=scan_id,
        )

        pro_cfg = get_default_config("pro")
        pro_model = pro_cfg.get("model") if pro_cfg else "gpt-4o"
        bt_update_profile(pid, status="running", pro_model=pro_model)

        def _bt_progress(pct, msg):
            from blueteam.api import _analysis_progress
            _analysis_progress[pid] = {"pct": pct, "msg": msg, "status": "running"}
            bt_update_profile(pid, status="running", scan_progress=pct)
            from redteam.scan_events import publish as bt_publish
            bt_publish(pid, "progress", {"pct": pct, "msg": msg})

        from blueteam.api import _running as bt_running
        bt_running.add(pid)

        def run_bt_analysis():
            try:
                from blueteam.ssdlc_scanner import SSDLCAnalyzer
                analyzer = SSDLCAnalyzer(
                    target_url=s.get("repo_url", ""),
                    user_id=user_id,
                    master_prompt=master_prompt,
                    documentation=documentation,
                    openapi_spec="",
                    collection_requests=[],
                    callbacks={"on_progress": _bt_progress},
                    analysis_rounds=6,
                    report_rounds=4,
                )
                result = analyzer.run()
                bt_create_report(
                    profile_id=pid,
                    report_md=result["report_markdown"],
                    findings_count=result["findings_count"],
                    analysis_rounds=result["analysis_rounds"],
                    tokens_used=result["tokens"].get("total", 0),
                    pro_model=result["pro_model"],
                )
                bt_update_profile(pid, status="completed", tokens_used=result["tokens"].get("total", 0))
                from redteam.scan_events import publish as bt_publish
                bt_publish(pid, "done", {"status": "completed"})
            except Exception as e:
                bt_update_profile(pid, status="failed")
                from redteam.scan_events import publish as bt_publish
                bt_publish(pid, "done", {"status": "failed"})
            finally:
                bt_running.discard(pid)
                from redteam.scan_events import cleanup as bt_cleanup
                bt_cleanup(pid)

        _log.info(f"Starting Blue Team remediation from Purple Team, bt_profile={pid}")
        thread = threading.Thread(target=run_bt_analysis, daemon=True)
        thread.start()

        return {"status": "started", "blueteam_profile_id": pid, "pro_model": pro_model}

    except ImportError as e:
        raise HTTPException(500, f"Blue Team module not available: {e}")
    except Exception as e:
        raise HTTPException(500, f"Failed to create Blue Team analysis: {e}")


# ═══════════════════════════════════════════
# REPO UPLOAD
# ═══════════════════════════════════════════

@app.post("/repos/upload")
async def api_upload_repo(request: Request, file: UploadFile = File(...)):
    """Upload a zip file containing source code."""
    if not file.filename or not file.filename.endswith((".zip", ".tar.gz", ".tgz")):
        raise HTTPException(400, "Only .zip, .tar.gz, or .tgz files are accepted")
    user_id = get_auth_user(request)
    try:
        content = await file.read()
        from purpleteam.repo_manager import store_uploaded_zip
        repo_path = store_uploaded_zip(content, file.filename, user_id)
        return {"repo_path": repo_path, "status": "uploaded"}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))
