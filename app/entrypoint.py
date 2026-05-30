# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 Elyria

import os
from fastapi import FastAPI, Request,HTTPException
from fastapi.responses import JSONResponse,HTMLResponse
from fastapi.staticfiles import StaticFiles

from request_manager.request_api import app as request_router
from database.request_log_api import app as data_router
from database.collection_api import app as collection_router
from ai_core.ai_api import app as ai_router
from auth_users.user_api import app as user_router
from doc_mgmt.document_api import app as document_router
from redteam.campaign_api import app as pentest_router
from blueteam.api import app as blueteam_router
from greyteam.api import app as greyteam_router
from database.workflow_graph_api import app as workflow_graph_router
from database.proxy_api import app as proxy_router
from database.teams_api import app as teams_router
from ai_core.ai_config_api import app as ai_config_router
from auth_users.oidc_api import app as oidc_router
from ely.api import app as ely_router

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import jwt
from database.user_mgmt import get_key

app = FastAPI()

"""# ── Gatekeeper (registered FIRST = outermost wall, runs before everything) ──
from database.app_config import get as _cfg
if _cfg("gatekeeper.enabled", "0") == "1":
from gatekeeper import gatekeeper_middleware as _gate_mw, gate_app as _gate_app
app.middleware("http")(_gate_mw)
app.include_router(_gate_app)"""

# ── CORS ──
if os.getenv("ELYRIA_PRODUCTION", "") == "1":
    _cors_origins = ["https://*.elyria.pro"]
else:
    _cors_origins = ["http://localhost:*", "http://127.0.0.1:*"]

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Audit logging middleware (outermost — runs first, finishes last) ──
from core.audit import audit_middleware, init_audit_db
init_audit_db()

app.middleware("http")(audit_middleware)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # Anti-MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Anti-clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Disable unused browser features
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # HSTS (browsers ignore on HTTP, safe to always set)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # CSP — script-src allows Tailwind CDN + inline (required by the SPA)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    return response


@app.middleware("http")
async def check_authorization(request: Request, call_next):
    # Only login/auth flows, HTML shells, and static assets are public.
    # HTML shells (/app, /workflow, etc.) are served without auth so the SPA
    # can load auth.js — client-side auth handles the rest.
    PUBLIC_ROUTES = {
        "/", "/login", "/app", "/workflow", "/pentest", "/greyteam", "/hub", "/doc", "/blueteam", "/m", "/gate",
        "/api/user/login", "/api/user/create", "/api/user/refresh",
        "/api/user/verify-email", "/api/user/resend-code",
        "/api/user/reset-password", "/api/user/reset-password/confirm",
        "/api/user/oidc/login", "/api/user/oidc/callback", "/api/user/oidc/config",
    }
    BLACKLISTED_PATHS = {"/docs", "/openapi.json", "/static/bundle.min.js", "/static/workflow-bundle.min.js",
                         "/static/pentest-bundle.min.js", "/static/blueteam-bundle.min.js"}
    if request.url.path in BLACKLISTED_PATHS:
        return JSONResponse(status_code=403, content={"detail": "Access to this resource is forbidden"})
    path = request.url.path
    if path in PUBLIC_ROUTES or path.startswith("/static/"):
        return await call_next(request)

    # SSE streams: EventSource can't send custom headers → bypass middleware
    if path.endswith("/events") and ("/api/blueteam/" in path or "/api/pentest/" in path or "/api/greyteam/" in path):
        return await call_next(request)

    auth = request.headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    token = auth.split("Bearer ")[1]
    if token.count(".") != 2:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    try:
        # Extract KID: header first (RFC 7515), fallback to payload (legacy)
        import base64 as _b64, json as _json
        kid = None
        parts = token.split(".")
        for idx in (0, 1):
            raw = parts[idx]
            raw += "=" * (4 - len(raw) % 4)
            try:
                obj = _json.loads(_b64.urlsafe_b64decode(raw))
                kid = obj.get("kid")
                if kid:
                    break
            except Exception:
                continue
        if not kid:
            return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})
        secret = get_key(kid)
        if not secret:
            return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})
        decoded = jwt.decode(token, secret, algorithms=["HS512"])
        request.state.token = decoded["sub"]
        request.state.token_obj = decoded
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})
    except jwt.InvalidTokenError:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    return await call_next(request)

@app.get("/")
async def serve_root():
    return _serve_html("login.html")

@app.get("/login")
async def serve_login():
    return _serve_html("login.html")

def _serve_html(filename: str) -> HTMLResponse:
    """Serve an HTML file. In production mode, inject cache-busting version."""
    try:
        with open(f"web_ui/{filename}", "r") as f:
            html = f.read()
        if os.getenv("ELYRIA_PRODUCTION", "") == "1":
            # Cache-busting: use file mtime as version
            import re
            bundle_path = "web_ui/static/bundle.min.js"
            v = str(int(os.path.getmtime(bundle_path))) if os.path.isfile(bundle_path) else "1"
            html = html.replace("{{VERSION}}", v)
            page = filename.replace(".html", "")
            bundle_map = {
                "index": "bundle.min.js",
                "workflow": "workflow-bundle.min.js",
                "redteam": "pentest-bundle.min.js",
                "blueteam": "blueteam-bundle.min.js",
                "greyteam": "greyteam-bundle.min.js",
            }
            js_bundle = bundle_map.get(page, "bundle.min.js")
            html = re.sub(r'<script src="https://cdn\.tailwindcss\.com[^<]*</script>', '', html)
            html = re.sub(r'<link[^>]*fonts\.googleapis\.com[^>]*>', '', html)
            html = re.sub(r'<link rel="stylesheet" href="static/styles\.css"[^>]*>',
                          f'<link rel="stylesheet" href="static/bundle.min.css?v={v}">', html)
            for script_src in ["static/auth.js", "static/app.js",
                               "static/workflow.js", "static/pentest.js", "static/blueteam.js",
                               "static/greyteam.js", "static/doc.js", "static/hub.js"]:
                html = re.sub(rf'<script src="{script_src}"[^>]*></script>', '', html)
            html = html.replace('</head>',
                                f'\n  <link rel="stylesheet" href="static/bundle.min.css?v={v}">\n</head>')
            html = html.replace('<body',
                                f'<body\n  <script src="static/{js_bundle}?v={v}"></script>')
        return HTMLResponse(content=html)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Frontend file not found")


@app.get("/app")
async def serve_app():
    return _serve_html("index.html")

@app.get("/workflow")
async def serve_workflow():
    return _serve_html("workflow.html")

@app.get("/hub")
async def serve_hub():
    return _serve_html("hub.html")

@app.get("/pentest")
async def serve_pentest():
    return _serve_html("redteam.html")

@app.get("/blueteam")
async def serve_blueteam():
    return _serve_html("blueteam.html")

@app.get("/greyteam")
async def serve_greyteam():
    return _serve_html("greyteam.html")

@app.get("/m")
async def serve_mobile():
    return _serve_html("m.html")

@app.get("/doc")
async def serve_doc():
    return _serve_html("doc.html")

# ── Enterprise & legal pages ──

def _serve_enterprise(filename: str) -> HTMLResponse:
    try:
        with open(f"../enterprise/pages/{filename}", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Page not found")

@app.get("/enterprise")
async def serve_enterprise():
    return _serve_enterprise("enterprise.html")

@app.get("/pricing")
async def serve_pricing():
    return _serve_enterprise("pricing.html")

@app.get("/edu")
async def serve_edu():
    return _serve_enterprise("edu.html")

@app.get("/legal")
async def serve_legal():
    return _serve_enterprise("legal.html")

@app.get("/privacy")
async def serve_privacy():
    return _serve_enterprise("privacy.html")

@app.get("/terms")
async def serve_terms():
    return _serve_enterprise("terms.html")

@app.get("/license")
async def serve_license():
    return HTMLResponse(content='<html><head><meta charset="UTF-8"><title>Licence — Elyria</title></head><body style="font-family:monospace;max-width:800px;margin:2rem auto;padding:0 1rem;background:#0a0f1c;color:#94a3b8;"><h1 style="color:#e5e7eb">Licence AGPL-3.0</h1><p>Elyria est distribue sous <strong>GNU Affero General Public License v3</strong>.</p><p>Texte complet : <a href="https://www.gnu.org/licenses/agpl-3.0.html" style="color:#8b5cf6">gnu.org/licenses/agpl-3.0.html</a></p><p>Pour une licence commerciale (SaaS, usage proprietaire) : <a href="mailto:contact@elyria.pro" style="color:#8b5cf6">contact@elyria.pro</a></p></body></html>')

@app.get("/api/doc")
async def get_doc(lang: str = "fr"):
    filename = "guide-utilisateur-en.md" if lang == "en" else "guide-utilisateur.md"
    try:
        with open(f"../doc/{filename}", "r") as f:
            return JSONResponse(content={"content": f.read(), "lang": lang})
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Documentation file not found")





app.mount("/static", StaticFiles(directory="web_ui/static", html=True), name="frontend")


app.include_router(request_router)
app.include_router(data_router)
app.include_router(collection_router)
app.include_router(ai_router)
app.include_router(user_router)
app.include_router(document_router)
app.include_router(pentest_router)
app.include_router(blueteam_router)
app.include_router(greyteam_router)
app.include_router(workflow_graph_router)
app.include_router(proxy_router)
app.include_router(teams_router)
app.include_router(ai_config_router)
app.include_router(oidc_router)
app.include_router(ely_router)

if __name__ == "__main__":
    import os
    import signal
    import subprocess
    import uvicorn
    from core.config import get, get_int, get_bool

    def _cleanup_sandboxes():
        """Kill all strike-* Docker containers before shutdown."""
        try:
            r = subprocess.run(
                ["docker", "ps", "-q", "--filter", "name=strike-"],
                capture_output=True, text=True, timeout=10,
            )
            ids = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
            if ids:
                subprocess.run(
                    ["docker", "rm", "-f"] + ids,
                    capture_output=True, timeout=30,
                )
                print(f"\n[elyria] Cleared {len(ids)} sandbox container(s)")
        except Exception:
            pass

    def _shutdown(signum, frame):
        print("\n[elyria] Ctrl+C received — cleaning up sandboxes...")
        _cleanup_sandboxes()
        print("[elyria] Shutting down.")
        os._exit(0)

    signal.signal(signal.SIGINT, _shutdown)

    cert = get("ssl", "cert_path")
    key = get("ssl", "key_path")
    ssl_kwargs = {}
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}

    uvicorn.run(
        "entrypoint:app",
        host=get("server", "host", "127.0.0.1"),
        port=get_int("server", "port", 8000),
        reload=get_bool("server", "reload", False),
        **ssl_kwargs,
        reload_dirs=["app/"],
        reload_excludes=["logs/*", "*.db"]
    )