# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

"""
Grey Team (OSINT) — FastAPI routes.

Endpoints:
  - /api/greyteam/profiles/*  — Profile CRUD (domain-targeted)
  - /api/greyteam/reports/*   — Report CRUD + passive OSINT scan
  - /api/greyteam/events/{report_id}  — SSE event stream

Scan flow:
  1. Create profile (name, target_domain, modules, rounds)
  2. Create report → triggers scan in daemon thread
  3. Phase 1: OSINTDomainScanner — deterministic passive collection (12 modules)
  4. Phase 2: AIOSINTRefiner — AI refinement + correlation (sandbox bash available)
"""

import asyncio
import json
import threading
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from database.connection import get_connection as _get_db_conn
from greyteam.database import (
    init_greyteam_db,
    create_profile, list_profiles, get_profile, update_profile, delete_profile,
    create_report, get_report, list_reports, update_report, delete_report,
    add_finding, get_report_findings, get_finding_counts, get_finding, delete_finding,
)
from greyteam.osint_scanner import OSINTDomainScanner

app = APIRouter(prefix="/api/greyteam", tags=["greyteam"])

# Initialize DB on module load
init_greyteam_db()

# ── Helpers ──

from core.auth import verify_ownership as _verify_ownership, get_user_teams as get_auth_user_teams, get_user as get_auth_user


def _sanitize_profile(p):
    for k in ("auth_config",):
        p.pop(k, None)
    return p


# ── SSE events (reusing redteam pub/sub) ──

_SCAN_EVENTS = {}  # report_id → asyncio.Queue

def _publish(report_id: str, event_type: str, data: dict):
    """Publish scan progress event."""
    from redteam.scan_events import publish as _p
    try:
        _p(report_id, event_type, data)
    except Exception:
        pass


def _cleanup_events(report_id: str):
    from redteam.scan_events import cleanup as _c
    try:
        _c(report_id)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
# Profiles CRUD
# ═══════════════════════════════════════════════════════════════

class CreateGreyProfileRequest(BaseModel):
    name: str
    team_ids: str = ""
    description: str = ""
    target_path: str = ""
    target_domain: str = ""
    categories: list = []
    explore_rounds: int = 15
    analysis_rounds: int = 5

@app.post("/profiles")
async def api_create_profile(body: CreateGreyProfileRequest, request: Request):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")
    pid = create_profile(
        name=name,
        user_id=get_auth_user(request),
        team_ids=body.team_ids or get_auth_user_teams(request),
        description=body.description,
        target_path=body.target_path,
        target_domain=body.target_domain,
        categories=body.categories,
        explore_rounds=body.explore_rounds,
        analysis_rounds=body.analysis_rounds,
    )
    return {"profile_id": pid}


@app.get("/profiles")
async def api_list_profiles(request: Request, team_id: str = ""):
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
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    reports = list_reports(profile_id=profile_id, user_id=get_auth_user(request), team_ids=get_auth_user_teams(request))
    for r in reports:
        r["finding_counts"] = get_finding_counts(r["report_id"])
    p["reports"] = reports
    return p


@app.put("/profiles/{profile_id}")
async def api_update_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    body = await request.json()
    updates = {}
    for k in ("name", "description", "target_path", "target_domain", "categories", "explore_rounds", "analysis_rounds"):
        if k in body:
            updates[k] = body[k]
    if updates:
        update_profile(profile_id, **updates)
    return {"updated": True}


@app.delete("/profiles/{profile_id}")
async def api_delete_profile(profile_id: str, request: Request):
    p = get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    delete_profile(profile_id)
    return {"deleted": True}


# ═══════════════════════════════════════════════════════════════
# Reports CRUD + Scan
# ═══════════════════════════════════════════════════════════════

class CreateReportRequest(BaseModel):
    profile_id: str
    name: str = ""
    description: str = ""
    categories: list = []
    target_path: str = ""
    target_domain: str = ""

@app.post("/reports")
async def api_create_report(_request: CreateReportRequest, request: Request):
    profile_id = _request.profile_id
    if not profile_id:
        raise HTTPException(400, "profile_id is required")

    p = get_profile(profile_id)
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))

    user_id = get_auth_user(request)

    rid = create_report(
        profile_id=profile_id,
        name=_request.name or p.get("name", "Unnamed Report"),
        description=_request.description or p.get("description", ""),
        categories=_request.categories or p.get("categories", "[]"),
        target_path=_request.target_path or p.get("target_path", ""),
        target_domain=_request.target_domain or p.get("target_domain", ""),
    )

    # Resolve target — domain takes priority over path
    domain = p.get("target_domain", "").strip()
    if not domain:
        raise HTTPException(400, "target_domain is required on the profile for OSINT scans")

    categories = p.get("categories", "[]")
    if isinstance(categories, str):
        try:
            categories = json.loads(categories)
        except (json.JSONDecodeError, TypeError):
            categories = []

    explore_rounds = int(p.get("explore_rounds", 15))
    analysis_rounds = int(p.get("analysis_rounds", 5))

    # Start scan in daemon thread
    def _run_scan():
        import traceback as _tb
        from core.logging import get_logger
        from greyteam.ai_osint_scanner import AIOSINTRefiner
        from sandbox.tool import BashTool
        from sandbox.manager import SandboxManager
        _log = get_logger("greyteam.api")

        _log.info(f"[greyteam] ===== Scan thread started: report={rid} domain={domain} modules={categories} =====")

        def _progress(pct, msg):
            _log.debug(f"[greyteam] Progress {pct}%: {msg}")
            update_report(rid, scan_progress=int(pct))
            _publish(rid, "progress", {"pct": int(pct), "msg": msg})

        def _on_finding(f):
            try:
                add_finding(
                    report_id=rid,
                    title=f.get("title", ""),
                    severity=f.get("severity", "medium"),
                    category=f.get("category", ""),
                    description=f.get("description", ""),
                    file_path=f.get("file_path", "N/A"),
                    line_number=f.get("line_number", 0),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    cwe_id=f.get("cwe_id", ""),
                    source=f.get("source", "deterministic"),
                    ai_description="",
                    finding_type=f.get("finding_type", "osint"),
                )
                _publish(rid, "finding", f)
            except Exception as e:
                _log.error(f"Failed to save finding: {e}")

        sandbox = None
        bash_tool = None
        try:
            # ── Phase 1: Deterministic OSINT collection ──
            _log.info(f"[greyteam] Phase 1 starting — domain={domain}")
            _progress(5, f"Starting passive OSINT collection for {domain}...")
            scanner = OSINTDomainScanner(
                domain=domain,
                progress_cb=_progress,
                modules=categories,
            )
            _log.info(f"[greyteam] Scanner initialized, running modules...")
            det_findings = scanner.run_all()
            _log.info(f"[greyteam] Phase 1 complete: {len(det_findings)} findings collected")

            # Save deterministic findings
            _log.info(f"[greyteam] Saving {len(det_findings)} deterministic findings to DB...")
            saved_count = 0
            for f in det_findings:
                try:
                    add_finding(
                        report_id=rid,
                        title=f.get("title", ""),
                        severity=f.get("severity", "medium"),
                        category=f.get("category", ""),
                        description=f.get("description", ""),
                        file_path=f.get("file_path", "N/A"),
                        line_number=f.get("line_number", 0),
                        evidence=f.get("evidence", ""),
                        remediation=f.get("remediation", ""),
                        cwe_id=f.get("cwe_id", ""),
                        source=f.get("source", "deterministic"),
                        ai_description="",
                        finding_type=f.get("finding_type", "osint"),
                    )
                    _publish(rid, "finding", f)
                    saved_count += 1
                except Exception:
                    pass

            _log.info(f"[greyteam] Saved {saved_count}/{len(det_findings)} findings to DB")
            _progress(90, f"Phase 1 complete: {len(det_findings)} findings. Starting AI refinement...")

            # ── Phase 2: AI Refinement ──
            _log.info(f"[greyteam] Phase 2 starting — spawning sandbox...")
            # Spawn sandbox if Docker is available
            try:
                mgr = SandboxManager()
                sandbox = mgr.spawn(target=domain)
                bash_tool = BashTool(sandbox=sandbox, manager=mgr, target=domain)
                _log.info(f"[greyteam] Sandbox spawned: container={sandbox.container_id}")
            except Exception as e:
                _log.warning(f"[greyteam] Sandbox not available, AI refiner will run without bash: {e}")

            try:
                _log.info(f"[greyteam] Phase 2 AI refiner starting — {analysis_rounds} rounds")
                # Re-fetch findings from DB with their DB IDs for the refiner
                db_findings = get_report_findings(rid)
                _log.info(f"[greyteam] Re-fetched {len(db_findings)} findings from DB for refiner")

                def _on_refine(finding):
                    """Update a finding with AI intelligence."""
                    try:
                        fid = finding.get("finding_id")
                        if not fid:
                            return
                        conn = _get_db_conn()
                        ai_desc = finding.get("ai_description", "")
                        exploit = finding.get("exploitability_score", 5)
                        priority = finding.get("remediation_priority", "informational")
                        attack = finding.get("attack_vector", "")
                        conn.execute(
                            """UPDATE greyteam_findings
                               SET ai_description=?, evidence=evidence || ?
                               WHERE finding_id=?""",
                            (ai_desc,
                             f"\n[AI] Exploitability: {exploit}/10 | Priority: {priority} | Vector: {attack}",
                             fid),
                        )
                        conn.commit()
                        conn.close()
                        _log.info(f"[greyteam] AI refine SAVED: finding_id={fid}, title={finding.get('title','')[:60]}, desc_len={len(ai_desc)}")
                        _publish(rid, "refine", finding)
                    except Exception as e:
                        _log.error(f"Failed to save AI refinement: {e}")

                def _on_chain(chain):
                    """Publish attack chain."""
                    _publish(rid, "chain", chain)

                def _on_create_finding(finding):
                    """Save a new AI-created finding to DB."""
                    try:
                        add_finding(
                            report_id=rid,
                            title=finding.get("title", ""),
                            severity=finding.get("severity", "medium"),
                            category=finding.get("category", "AI Discovery"),
                            description=finding.get("description", ""),
                            file_path=finding.get("file_path", "N/A"),
                            line_number=finding.get("line_number", 0),
                            evidence=finding.get("evidence", ""),
                            remediation=finding.get("remediation", ""),
                            cwe_id=finding.get("cwe_id", ""),
                            source="ai",
                            ai_description=finding.get("ai_description", ""),
                            finding_type=finding.get("finding_type", "osint"),
                        )
                        _publish(rid, "finding", finding)
                        _log.info(f"[greyteam] AI created new finding: {finding.get('title', '')}")
                    except Exception as e:
                        _log.error(f"Failed to save AI-created finding: {e}")

                refiner = AIOSINTRefiner(
                    report_id=rid,
                    domain=domain,
                    user_id=user_id,
                    deterministic_findings=db_findings,
                    callbacks={
                        "on_progress": _progress,
                        "on_refine": _on_refine,
                        "on_chain": _on_chain,
                        "on_create_finding": _on_create_finding,
                    },
                    description=p.get("description", ""),
                    rounds=analysis_rounds,
                    bash_tool=bash_tool,
                )
                ai_result = refiner.run()
                tokens = ai_result.get("tokens", {})
                update_report(
                    rid,
                    tokens_used=tokens.get("total", 0),
                    pro_model=ai_result.get("pro_model", ""),
                    analysis_rounds=ai_result.get("refinements", 0) + ai_result.get("created", 0),
                    report_markdown=ai_result.get("summary", ""),
                )
                _log.info(
                    f"[greyteam] AI refinement complete: {ai_result.get('refinements', 0)} refined, "
                    f"{ai_result.get('created', 0)} created, "
                    f"{len(ai_result.get('chains', []))} chains, "
                    f"tokens={tokens.get('total', 0)}"
                )
            except RuntimeError as e:
                if "No AI providers" in str(e):
                    _log.warning(f"[greyteam] AI refinement skipped — no AI provider configured")
                    _progress(90, "AI refinement skipped — no AI provider configured")
                else:
                    _log.error(f"[greyteam] AI refiner RuntimeError: {e}")
                    raise
            except Exception as e:
                _log.error(f"[greyteam] AI refinement failed: {e}\n{_tb.format_exc()}")
                _progress(90, f"AI refinement failed: {str(e)[:100]}")

            _progress(100, "OSINT scan complete")
            update_report(rid, status="completed")
            _publish(rid, "done", {"status": "completed"})
            _log.info(f"[greyteam] ===== Scan complete: report={rid} =====")

        except Exception as e:
            _log.error(f"[greyteam] Scan failed: {e}\n{_tb.format_exc()}")
            update_report(rid, status="failed")
            _publish(rid, "done", {"status": "failed", "error": str(e)[:200]})
        finally:
            if sandbox:
                try:
                    _log.info(f"[greyteam] Destroying sandbox: {sandbox.container_id}")
                    sandbox.destroy()
                except Exception as e:
                    _log.warning(f"[greyteam] Failed to destroy sandbox: {e}")
            _cleanup_events(rid)
            _log.info(f"[greyteam] ===== Scan thread exiting: report={rid} =====")

    from core.logging import get_logger
    _prelog = get_logger("greyteam.api")
    _prelog.info(f"[greyteam] Creating report {rid} for profile={profile_id} domain={domain} modules={categories}")

    t = threading.Thread(target=_run_scan, daemon=True)
    t.start()
    _prelog.info(f"[greyteam] Scan thread launched: {t.name} alive={t.is_alive()}")

    return {"report_id": rid}


@app.get("/reports")
async def api_list_reports(request: Request, profile_id: str = ""):
    reports = list_reports(
        profile_id=profile_id,
        user_id=get_auth_user(request),
        team_ids=get_auth_user_teams(request),
    )
    for r in reports:
        r["finding_counts"] = get_finding_counts(r["report_id"])
    return reports


@app.get("/reports/{report_id}")
async def api_get_report(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    # Verify ownership via the profile
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if p:
        _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    r["finding_counts"] = get_finding_counts(report_id)
    return r


@app.delete("/reports/{report_id}")
async def api_delete_report(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if p:
        _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    delete_report(report_id)
    return {"deleted": True}


@app.post("/reports/{report_id}/stop")
async def api_stop_scan(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if p:
        _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    return {"stopped": "graceful_stop_not_available"}


# ═══════════════════════════════════════════════════════════════
# Findings
# ═══════════════════════════════════════════════════════════════

@app.get("/reports/{report_id}/findings")
async def api_get_findings(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    findings = get_report_findings(report_id)
    counts = get_finding_counts(report_id)
    return {"findings": findings, "counts": counts, "total": len(findings)}


@app.get("/findings/{finding_id}")
async def api_get_finding(finding_id: str, request: Request):
    f = get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    # Verify ownership via report → profile
    r = get_report(f["report_id"])
    if not r:
        raise HTTPException(404, "Report not found")
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    return f


@app.delete("/findings/{finding_id}")
async def api_delete_finding(finding_id: str, request: Request):
    f = get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    r = get_report(f["report_id"])
    if not r:
        raise HTTPException(404, "Report not found")
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if not p:
        raise HTTPException(404, "Profile not found")
    _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    delete_finding(finding_id)
    return {"deleted": True}


# ═══════════════════════════════════════════════════════════════
# SSE events
# ═══════════════════════════════════════════════════════════════

@app.get("/events/{report_id}")
async def api_events(report_id: str, request: Request):
    r = get_report(report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    from greyteam.database import get_profile as _gp
    p = _gp(r["profile_id"])
    if p:
        _verify_ownership(p, get_auth_user(request), get_auth_user_teams(request))
    from redteam.scan_events import subscribe, heartbeat
    async def event_stream():
        async for event in subscribe(report_id):
            yield event
    return StreamingResponse(event_stream(), media_type="text/event-stream")
