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
from database.workflow_graph_api import app as workflow_graph_router
from database.proxy_api import app as proxy_router
from database.teams_api import app as teams_router
from ai_core.ai_config_api import app as ai_config_router
from catcher.catcher_api import app as catcher_router
from database.app_config_api import app as app_config_router
from auth_users.oidc_api import app as oidc_router

import jwt
from database.user_mgmt import get_key

app = FastAPI()

# ── Audit logging middleware (outermost — runs first, finishes last) ──
from core.audit import audit_middleware, init_audit_db
init_audit_db()

app.middleware("http")(audit_middleware)


@app.middleware("http")
async def check_authorization(request: Request, call_next):
    # Only login/auth flows, HTML shells, and static assets are public.
    # HTML shells (/app, /workflow, etc.) are served without auth so the SPA
    # can load auth.js — client-side auth handles the rest.
    PUBLIC_ROUTES = {
        "/", "/login", "/app", "/workflow", "/pentest", "/hub", "/doc", "/blueteam",
        "/api/user/login", "/api/user/create", "/api/user/refresh",
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
    if path.endswith("/events") and ("/api/blueteam/" in path or "/api/pentest/" in path):
        return await call_next(request)

    auth = request.headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    token = auth.split("Bearer ")[1]
    if token.count(".") != 2:
        return JSONResponse(status_code=401, content={"detail": "Invalid Authorization format"})

    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        kid = unverified.get("kid")
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
            }
            js_bundle = bundle_map.get(page, "bundle.min.js")
            html = re.sub(r'<script src="https://cdn\.tailwindcss\.com[^<]*</script>', '', html)
            html = re.sub(r'<link[^>]*fonts\.googleapis\.com[^>]*>', '', html)
            html = re.sub(r'<link rel="stylesheet" href="static/styles\.css"[^>]*>',
                          f'<link rel="stylesheet" href="static/bundle.min.css?v={v}">', html)
            for script_src in ["static/auth.js", "static/app.js", "static/catcher.js",
                               "static/workflow.js", "static/pentest.js", "static/blueteam.js",
                               "static/doc.js", "static/hub.js"]:
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

@app.get("/doc")
async def serve_doc():
    return _serve_html("doc.html")

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
app.include_router(workflow_graph_router)
app.include_router(proxy_router)
app.include_router(teams_router)
app.include_router(ai_config_router)
app.include_router(catcher_router)
app.include_router(app_config_router)
app.include_router(oidc_router)


if __name__ == "__main__":
    import os
    import uvicorn
    from database.app_config import get

    cert = get("ssl.cert_path")
    key = get("ssl.key_path")
    ssl_kwargs = {}
    if cert and key and os.path.isfile(cert) and os.path.isfile(key):
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}

    uvicorn.run(
        "entrypoint:app",
        host=get("app.host", "127.0.0.1"),
        port=int(get("app.port", "8000")),
        reload=get("app.reload", "0") == "1",
        **ssl_kwargs,
    )